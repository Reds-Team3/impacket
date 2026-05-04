from __future__ import print_function

import sys
import socket
import struct
import uuid as _uuid_mod
import argparse
import logging
import getpass

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def init_logger(add_ts=False, debug=False):
    level = logging.DEBUG if debug else logging.INFO
    fmt = '%(asctime)s ' if add_ts else ''
    fmt += '%(levelname)s: %(message)s'
    logging.basicConfig(level=level, format=fmt)


# ---------------------------------------------------------------------------
# DCE/RPC constants
# ---------------------------------------------------------------------------

MSRPC_VERSION       = 5
MSRPC_MINOR_VERSION = 0

MSRPC_BIND          = 11
MSRPC_BIND_ACK      = 12
MSRPC_REQUEST       = 0
MSRPC_RESPONSE      = 2
MSRPC_FAULT         = 3

PFC_FIRST_FRAG      = 0x01
PFC_LAST_FRAG       = 0x02
REPRESENTATION_LE   = 0x10   # little-endian, ASCII

# EPM interface
EPMAPPER_UUID        = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
EPMAPPER_VERSION     = 3
EPMAPPER_VERSION_MIN = 0

# NDR transfer syntax
NDR_UUID    = '8a885d04-1ceb-11c9-9fe8-08002b104860'
NDR_VERSION = 2

EPT_LOOKUP  = 2   # ept_lookup opnum
MAX_ENTRIES = 500


# ---------------------------------------------------------------------------
# UUID helpers
# ---------------------------------------------------------------------------

def pack_uuid_bytes(uuid_str):
    """UUID string → 16-byte DCE wire format (bytes_le)."""
    return _uuid_mod.UUID(uuid_str).bytes_le


def unpack_uuid_bytes(data, offset=0):
    """16 bytes of DCE wire UUID (bytes_le) → UUID string."""
    raw = data[offset:offset + 16]
    if len(raw) != 16:
        raise ValueError(
            "Need 16 bytes for UUID, got %d (offset=%d, buf_len=%d)"
            % (len(raw), offset, len(data))
        )
    return str(_uuid_mod.UUID(bytes_le=bytes(raw)))


# ---------------------------------------------------------------------------
# DCE/RPC PDU helpers
# ---------------------------------------------------------------------------

def build_common_header(ptype, frag_len, call_id, flags=PFC_FIRST_FRAG | PFC_LAST_FRAG):
    """16-byte DCE/RPC common header."""
    return bytes([
        MSRPC_VERSION,          # rpc_vers
        MSRPC_MINOR_VERSION,    # rpc_vers_minor
        ptype,                  # PTYPE
        flags,                  # pfc_flags
        REPRESENTATION_LE,      # packed_drep[0]: byte order + charset
        0x00,                   # packed_drep[1]: float format
        0x00,                   # packed_drep[2]: reserved
        0x00,                   # packed_drep[3]: reserved
    ]) + struct.pack('<HHI', frag_len, 0, call_id)
    #                frag_len  auth_len  call_id


def build_bind_pdu(call_id=1):
    """MSRPC BIND PDU: bind to EPM interface with NDR transfer syntax."""
    epm_uuid_b = pack_uuid_bytes(EPMAPPER_UUID)
    ndr_uuid_b = pack_uuid_bytes(NDR_UUID)

    # p_syntax_id (interface): uuid(16) + ver_major(2) + ver_minor(2)
    if_id = epm_uuid_b + struct.pack('<HH', EPMAPPER_VERSION, EPMAPPER_VERSION_MIN)
    # transfer syntax: uuid(16) + version(2) + minor(2)
    xfer  = ndr_uuid_b + struct.pack('<HH', NDR_VERSION, 0)

    # p_cont_list: num_contexts(2) + reserved(2) + [ctx_id(2) + num_xfer_syn(2) + if_id(20) + xfer(20)]
    p_context_elem = struct.pack('<HH', 1, 0) + struct.pack('<HH', 0, 1) + if_id + xfer

    # BIND body: max_xmit(2) + max_recv(2) + assoc_group(4) + p_context_elem
    bind_body = struct.pack('<HHI', 4280, 4280, 0) + p_context_elem

    frag_len = 16 + len(bind_body)
    return build_common_header(MSRPC_BIND, frag_len, call_id) + bind_body


def parse_bind_ack(data):
    """Parse BIND_ACK; raise on rejection or wrong PDU type."""
    if len(data) < 16:
        raise ValueError("BIND_ACK too short (%d bytes)" % len(data))
    ptype = data[2]
    if ptype == MSRPC_FAULT:
        status = struct.unpack_from('<I', data, 16)[0] if len(data) >= 20 else 0
        raise RuntimeError("BIND fault, status=0x%08x" % status)
    if ptype != MSRPC_BIND_ACK:
        raise RuntimeError("Expected BIND_ACK (12), got ptype=%d" % ptype)
    # secondary_addr_len at offset 24 (2 bytes), then the addr string
    if len(data) < 26:
        raise ValueError("BIND_ACK too short for secondary_addr")
    sec_addr_len = struct.unpack_from('<H', data, 24)[0]
    # skip to p_results, 4-byte aligned after secondary_addr
    offset = 26 + sec_addr_len
    offset = (offset + 3) & ~3
    if offset + 4 > len(data):
        raise ValueError("BIND_ACK too short for p_results")
    num_results = struct.unpack_from('<H', data, offset)[0]
    offset += 4
    for _ in range(num_results):
        if offset + 2 > len(data):
            break
        result = struct.unpack_from('<H', data, offset)[0]
        if result == 0:
            return True
        offset += 24   # result(2)+reason(2)+transfer_syntax(20)
    raise RuntimeError("All p_context items rejected in BIND_ACK")


def build_request_pdu(call_id, opnum, stub_data):
    """MSRPC REQUEST PDU."""
    # alloc_hint(4) + p_context_id(2) + opnum(2)
    req_hdr = struct.pack('<IHH', len(stub_data), 0, opnum)
    body = req_hdr + stub_data
    frag_len = 16 + len(body)
    return build_common_header(MSRPC_REQUEST, frag_len, call_id) + body


# ---------------------------------------------------------------------------
# NDR: ept_lookup request encoding
# ---------------------------------------------------------------------------

def build_ept_lookup_request(entry_handle_bytes=None):
    """
    NDR-encode ept_lookup() call:
        inquiry_type = RPC_C_EP_ALL_ELTS (0)
        object       = NULL pointer
        interface_id = NULL pointer
        vers_option  = 0
        entry_handle = 20-byte context handle
        max_ents     = MAX_ENTRIES
    """
    if entry_handle_bytes is None:
        entry_handle_bytes = b'\x00' * 20

    return (
        struct.pack('<I', 0)               # inquiry_type = 0
        + struct.pack('<I', 0)             # *object = NULL
        + struct.pack('<I', 0)             # *interface_id = NULL
        + struct.pack('<I', 0)             # vers_option = 0
        + bytes(entry_handle_bytes)        # entry_handle (20 bytes)
        + struct.pack('<I', MAX_ENTRIES)   # max_ents
    )


# ---------------------------------------------------------------------------
# NDR: ept_lookup response decoding
#
# Wire layout of ept_entry_t (NDR-encoded):
#   object        : UUID (16 bytes, bytes_le)
#   tower         : unique pointer (4-byte referent ID)
#   annotation    : char[64]  ← FIXED SIZE, NOT a conformant string!
#
# The entries array is conformant:
#   max_count (4 bytes) precedes the array elements.
#
# After the entries array, deferred tower data is appended for each
# non-NULL tower pointer (conformant blob: max_count(4) + tower_len(4)
# + floor data).
#
# After all deferred data:
#   num_ents (4 bytes)   ← actual count returned
#   status   (4 bytes)
# ---------------------------------------------------------------------------

ANNOTATION_SIZE = 64  # char annotation[64]


def _align4(offset):
    return (offset + 3) & ~3


def parse_ept_lookup_response(stub):
    """
    Parse NDR stub data of ept_lookup response.

    Returns: (entry_handle_bytes, entries_list, status_code)
    Each entry: {'object_uuid': str, 'annotation': str, 'tower_floors': list}
    """
    offset = 0

    # ── entry_handle: 20-byte context handle ──────────────────────────────
    if len(stub) < offset + 20:
        raise ValueError("stub too short for entry_handle")
    entry_handle = stub[offset:offset + 20]
    offset += 20

    # ── num_ents: actual count returned (unsigned32) ───────────────────────
    if len(stub) < offset + 4:
        raise ValueError("stub too short for num_ents")
    num_ents = struct.unpack_from('<I', stub, offset)[0]
    offset += 4

    # ── conformant array: max_count ───────────────────────────────────────
    if len(stub) < offset + 4:
        raise ValueError("stub too short for max_count")
    max_count = struct.unpack_from('<I', stub, offset)[0]
    offset += 4

    # ── array elements (fixed-layout, no deferred data in-line) ───────────
    # Each ept_entry_t element on the wire:
    #   object UUID : 16 bytes
    #   tower ptr   :  4 bytes (referent or 0)
    #   annotation  : 64 bytes (fixed char array)
    entries_raw = []
    for _ in range(max_count):
        if len(stub) < offset + 16 + 4 + ANNOTATION_SIZE:
            break

        obj_uuid = unpack_uuid_bytes(stub, offset)
        offset += 16

        tower_referent = struct.unpack_from('<I', stub, offset)[0]
        offset += 4

        raw_ann = stub[offset:offset + ANNOTATION_SIZE]
        offset += ANNOTATION_SIZE
        try:
            annotation = raw_ann.rstrip(b'\x00').decode('utf-8', errors='replace')
        except Exception:
            annotation = ''

        entries_raw.append({
            'object_uuid':     obj_uuid,
            'annotation':      annotation,
            'tower_referent':  tower_referent,
            'tower_floors':    [],
        })

    # ── deferred tower data: one blob per non-NULL referent ───────────────
    for entry in entries_raw:
        if entry['tower_referent'] == 0:
            continue
        if len(stub) < offset + 8:
            break
        # conformant blob: max_count(4) = total byte length
        tower_max = struct.unpack_from('<I', stub, offset)[0]
        offset += 4
        # actual length field (repeated in some implementations)
        tower_len = struct.unpack_from('<I', stub, offset)[0]
        offset += 4
        if len(stub) < offset + tower_len:
            tower_len = len(stub) - offset   # clamp rather than crash
        tower_bytes = stub[offset:offset + tower_len]
        offset += tower_len
        # towers are NOT 4-byte-aligned between entries in standard EPM
        entry['tower_floors'] = parse_tower(tower_bytes)

    # ── trailing status (last 4 bytes) ────────────────────────────────────
    status = 0
    if len(stub) >= offset + 4:
        status = struct.unpack_from('<I', stub, offset)[0]

    return entry_handle, entries_raw[:num_ents], status


# ---------------------------------------------------------------------------
# Tower parsing
# ---------------------------------------------------------------------------

def parse_tower(data):
    """
    Parse a DCE/RPC protocol tower.

    Tower wire format:
        num_floors  (2 bytes, LE)
        [floor]*    each floor:
            lhs_len (2 bytes, LE)
            lhs      (lhs_len bytes) — protocol ID + optional UUID + versions
            rhs_len (2 bytes, LE)
            rhs      (rhs_len bytes) — port, address, pipe name …

    Floor 0: protocol_id=0x0d, lhs = [0x0d][16-byte UUID][2-byte ver][2-byte ver_minor]
    Floor 1: protocol_id=0x0d, lhs = [0x0d][16-byte NDR UUID][2-byte ver][2-byte ver_minor]
    Floor 2: transport protocol (0x07=ncacn_ip_tcp, 0x08=ncadg_ip_udp, 0x0f=ncacn_np …)
    Floor 3: address (IP, pipe, …)
    Floor 4: (sometimes) port
    """
    if len(data) < 2:
        return []
    num_floors = struct.unpack_from('<H', data, 0)[0]
    offset = 2
    floors = []
    for _ in range(num_floors):
        if offset + 2 > len(data):
            break
        lhs_len = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if offset + lhs_len > len(data):
            break
        lhs = data[offset:offset + lhs_len]
        offset += lhs_len

        if offset + 2 > len(data):
            break
        rhs_len = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if offset + rhs_len > len(data):
            break
        rhs = data[offset:offset + rhs_len]
        offset += rhs_len

        proto_id = lhs[0] if lhs else 0
        floors.append({'lhs': lhs, 'rhs': rhs, 'protocol_id': proto_id})
    return floors


def get_uuid_from_floor0(floors):
    """
    Extract the interface UUID from floor 0.

    Floor 0 LHS layout: [1-byte proto_id=0x0d][16-byte UUID bytes_le][2+2 byte versions]
    UUID starts at byte offset 1.
    """
    if not floors:
        return None
    lhs = floors[0]['lhs']
    if len(lhs) < 17:   # need at least proto_id(1) + UUID(16)
        return None
    try:
        return unpack_uuid_bytes(lhs, 1)   # skip the 1-byte protocol identifier
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Binding string formatter
# ---------------------------------------------------------------------------

# Floor 2 protocol IDs → transport name
TRANSPORT_PROTO = {
    0x07: 'ncacn_ip_tcp',
    0x08: 'ncadg_ip_udp',
    0x09: 'ncacn_nb_nb',
    0x0c: 'ncacn_spx',
    0x0d: 'ncacn_ip_tcp',   # seen in some stacks
    0x0e: 'ncadg_ip_udp',
    0x0f: 'ncacn_np',
    0x10: 'ncacn_np',
    0x11: 'ncalrpc',
    0x1f: 'ncacn_http',
    0x04: 'ncacn_dnet_nsp',
}

# UUID (lowercase, without version) → human-readable name
KNOWN_UUID_PROTOCOLS = {
    '6bffd098-a112-3610-9833-46c3f87e345a': 'Workstation Service',
    '4b112204-0e19-11d3-b42b-0000f81feb9f': 'Svcctl',
    '367abb81-9844-35f1-ad32-98f038001003': 'Svcctl',
    '12345778-1234-abcd-ef00-0123456789ab': 'LSASS (lsarpc)',
    '12345678-1234-abcd-ef00-01234567cffb': 'LSASS (netlogon)',
    '3919286a-b10c-11d0-9ba8-00c04fd92ef5': 'LSASS (dsrole)',
    '338cd001-2244-31f1-aaaa-900038001003': 'Remote Registry',
    '4da1c422-943d-11d1-acae-00c04fc2aa3f': 'DCOM',
    '000001a0-0000-0000-c000-000000000046': 'DCOM',
    '99fcfec4-5260-101b-bbcb-00aa0021347a': 'DCOM IOxidResolver',
    'e60c73e6-88f9-11cf-9af1-0020af6e72f4': 'COM+ WOW Interface',
    'ecec0d70-a603-11d0-96b1-00a0c91ece30': 'Crypto Services',
    '82ad4280-036b-11cf-972c-00aa006887b0': 'IIS',
    '8cfb5d70-31a4-11cf-a7d8-00805f48a135': 'IIS',
    '1ff70682-0a51-30e8-076d-740be8cee98b': 'Task Scheduler',
    '378e52b0-c0a9-11cf-822d-00aa0051e40f': 'Task Scheduler',
    '0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53': 'Task Scheduler 2.0',
    '86d35949-83c9-4044-b424-db363231fd0c': 'Task Scheduler 2.0',
    '30adc50c-5cbc-46ce-9a0e-91914789e23c': 'Task Scheduler 2.0',
    '65a93890-fab9-43a3-b2a5-1e330ac28f11': 'Task Scheduler 2.0',
    'a398e520-d59a-4bdd-aa7a-3c1e0303a511': 'Task Scheduler 2.0',
    '76d12b80-767c-11d2-bad9-00609794f271': 'MSMQ',
    'fdb3a030-065f-11d1-bb9b-00a024ea5525': 'MSMQ',
    '41208ee0-e970-11d1-9b9e-00e02c064c39': 'MSMQ',
    '2f5f3220-c126-1076-b549-074d078619da': 'Network DDE',
    '2f5f3222-c126-1076-b549-074d078619da': 'Network DDE',
    '906b0ce0-c70b-1067-b317-00dd010662da': 'RPC Locator / Endpoint Mapper',
    'e1af8308-5d1f-11c9-91a4-08002b14a0fa': 'Endpoint Mapper',
    '8d9f4e40-a03d-11ce-8f69-08003e30051b': 'Plug and Play',
    '894de0c0-0d55-11d3-a322-00c04fa321a1': 'Plug and Play (winmgmt)',
    '3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5': 'DHCP Client',
    '3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6': 'DHCP Client (alt)',
    '45f52c28-7f9f-101a-b52b-08002b2efabe': 'WINS',
    '811109bf-a4e1-11d1-ab54-00a0c91e9b45': 'WINS',
    'bfa951d1-2f0e-11d3-bfd1-00c04fa3490a': 'WINS',
    'f5cc59b4-4264-101a-8c59-08002b2f8426': 'File Replication',
    'd049b186-814f-11d1-9a3c-00c04fc9b232': 'File Replication',
    'a00c021c-2be2-11d2-b678-0000f87a8f8e': 'File Replication',
    'fc683bff-952e-11d2-8276-0000f87a8f8e': 'File Replication',
    'db6b59c4-8a94-11d2-8278-0000f87a8f8e': 'File Replication',
    'c9378ff1-16f7-11d0-a0b2-00aa0061426a': 'PAStore Engine',
}

KNOWN_UUID_EXES = {
    '6bffd098-a112-3610-9833-46c3f87e345a': 'wkssvc.exe',
    '4b112204-0e19-11d3-b42b-0000f81feb9f': 'services.exe',
    '367abb81-9844-35f1-ad32-98f038001003': 'services.exe',
    '12345778-1234-abcd-ef00-0123456789ab': 'lsass.exe',
    '12345678-1234-abcd-ef00-01234567cffb': 'lsass.exe',
    '3919286a-b10c-11d0-9ba8-00c04fd92ef5': 'lsass.exe',
    '338cd001-2244-31f1-aaaa-900038001003': 'regsvc.dll',
    '1ff70682-0a51-30e8-076d-740be8cee98b': 'mstask.exe',
    '378e52b0-c0a9-11cf-822d-00aa0051e40f': 'mstask.exe',
    'e1af8308-5d1f-11c9-91a4-08002b14a0fa': 'rpcss.dll',
    '906b0ce0-c70b-1067-b317-00dd010662da': 'rpcss.dll',
}


def floor_to_binding_string(floors):
    """
    Reconstruct a binding string from parsed tower floors.

    Typical 5-floor TCP tower:
      Floor 0: interface UUID + version
      Floor 1: NDR transfer syntax
      Floor 2: transport protocol (e.g. 0x07 = ncacn_ip_tcp)
      Floor 3: IP address (4 bytes, big-endian)
      Floor 4: TCP port (2 bytes, big-endian)
    """
    if not floors:
        return 'N/A'
    try:
        # Determine transport from floor 2
        proto_id = floors[2]['protocol_id'] if len(floors) > 2 else 0
        proto    = TRANSPORT_PROTO.get(proto_id, 'unknown_proto(0x%02x)' % proto_id)

        parts = []
        # Floors 3+ carry address info
        for fl in floors[3:]:
            rhs = fl['rhs']
            pid = fl['protocol_id']

            if pid in (0x07, 0x0d):   # TCP port (big-endian 16-bit)
                if len(rhs) >= 2:
                    port = struct.unpack('>H', rhs[:2])[0]
                    parts.append('[%d]' % port)
            elif pid in (0x08, 0x0e): # UDP port
                if len(rhs) >= 2:
                    port = struct.unpack('>H', rhs[:2])[0]
                    parts.append('[%d]' % port)
            elif pid == 0x09:         # IP address (4 bytes)
                if len(rhs) == 4:
                    parts.append('%d.%d.%d.%d' % tuple(rhs))
            elif pid in (0x0f, 0x10): # named pipe
                s = rhs.rstrip(b'\x00').decode('utf-8', errors='replace')
                if s:
                    parts.append('[%s]' % s)
            elif pid == 0x11:         # ncalrpc endpoint name
                s = rhs.rstrip(b'\x00').decode('utf-8', errors='replace')
                if s:
                    parts.append('[%s]' % s)
            else:
                if rhs:
                    s = rhs.rstrip(b'\x00').decode('utf-8', errors='replace')
                    if s and s.isprintable():
                        parts.append(s)

        return proto + ':' + ''.join(parts) if parts else proto

    except Exception as ex:
        return 'parse_error(%s)' % ex


# ---------------------------------------------------------------------------
# Transport: raw TCP with PDU reassembly
# ---------------------------------------------------------------------------

class TCPTransport:
    def __init__(self, host, port=135, timeout=10):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self._sock   = None

    def connect(self):
        logging.debug("Connecting to %s:%d" % (self.host, self.port))
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

    def send(self, data):
        self._sock.sendall(data)

    def recv_pdu(self):
        """Read one complete MSRPC PDU, reassembling fragments."""
        hdr  = self._recv_n(16)
        flen = struct.unpack_from('<H', hdr, 8)[0]
        pdu  = hdr + self._recv_n(flen - 16)

        while not (pdu[3] & PFC_LAST_FRAG):
            # read next fragment header + body
            frag_hdr  = self._recv_n(16)
            frag_flen = struct.unpack_from('<H', frag_hdr, 8)[0]
            frag_body = self._recv_n(frag_flen - 16)
            # skip per-fragment request header (8 bytes) before appending stub
            pdu += frag_body[8:]

        return pdu

    def _recv_n(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("Socket closed after %d/%d bytes" % (len(buf), n))
            buf += chunk
        return buf

    def disconnect(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# EPM client
# ---------------------------------------------------------------------------

class EPMClient:
    def __init__(self, host, port=135, timeout=10):
        self._transport = TCPTransport(host, port, timeout)
        self._call_id   = 1

    def connect(self):
        self._transport.connect()
        pdu = build_bind_pdu(call_id=self._call_id)
        self._transport.send(pdu)
        resp = self._transport.recv_pdu()
        parse_bind_ack(resp)
        self._call_id += 1

    def lookup_all(self):
        """Iteratively drain the endpoint mapper table."""
        all_entries  = []
        entry_handle = b'\x00' * 20

        while True:
            stub = build_ept_lookup_request(entry_handle)
            req  = build_request_pdu(self._call_id, EPT_LOOKUP, stub)
            self._call_id += 1
            self._transport.send(req)
            resp = self._transport.recv_pdu()

            ptype = resp[2]
            if ptype == MSRPC_FAULT:
                status = struct.unpack_from('<I', resp, 24)[0] if len(resp) >= 28 else 0
                raise RuntimeError("RPC_FAULT in ept_lookup: 0x%08x" % status)
            if ptype != MSRPC_RESPONSE:
                raise RuntimeError("Unexpected PDU type %d" % ptype)

            # Stub data starts after 16-byte common header +
            # 8-byte response header (alloc_hint + p_context_id + cancel_count + reserved)
            stub_data = resp[24:]

            entry_handle, entries, ept_status = parse_ept_lookup_response(stub_data)
            all_entries.extend(entries)

            # 0x16c9a0d6 = EPT_S_NOT_REGISTERED (no more entries)
            if ept_status != 0 or len(entries) == 0:
                break

        return all_entries

    def disconnect(self):
        self._transport.disconnect()


# ---------------------------------------------------------------------------
# Main dump logic
# ---------------------------------------------------------------------------

class RPCDump:
    def __init__(self, port=135, timeout=10):
        self._port    = port
        self._timeout = timeout

    def dump(self, remote_name, remote_host):
        logging.info("Retrieving endpoint list from %s" % remote_name)

        client = EPMClient(remote_host, self._port, self._timeout)
        try:
            client.connect()
        except Exception as e:
            logging.critical("Failed to connect to %s:%d — %s" % (remote_host, self._port, e))
            return

        try:
            entries = client.lookup_all()
        except Exception as e:
            logging.critical("Protocol failed: %s" % e)
            return
        finally:
            client.disconnect()

        if not entries:
            logging.info("No endpoints found.")
            return

        # Group by interface UUID
        endpoints = {}
        for entry in entries:
            floors   = entry.get('tower_floors', [])
            if_uuid  = get_uuid_from_floor0(floors) or entry.get('object_uuid', 'unknown')
            key      = if_uuid.lower()

            if key not in endpoints:
                endpoints[key] = {
                    'uuid':       if_uuid,
                    'annotation': entry.get('annotation', ''),
                    'bindings':   [],
                    'exe':        KNOWN_UUID_EXES.get(key, 'N/A'),
                    'protocol':   KNOWN_UUID_PROTOCOLS.get(key, 'N/A'),
                }

            binding = floor_to_binding_string(floors)
            if binding not in endpoints[key]['bindings']:
                endpoints[key]['bindings'].append(binding)

            if not endpoints[key]['annotation'] and entry.get('annotation'):
                endpoints[key]['annotation'] = entry['annotation']

        for key, ep in endpoints.items():
            print("Protocol: %s " % ep['protocol'])
            print("Provider: %s " % ep['exe'])
            print("UUID    : %s %s" % (ep['uuid'], ep['annotation']))
            print("Bindings: ")
            for b in ep['bindings']:
                print("          %s" % b)
            print("")

        num = len(entries)
        logging.info("Received %d endpoint%s." % (num, '' if num == 1 else 's'))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_target(target):
    """[[domain/]username[:password]@]<host> → (domain, user, pass, host)"""
    domain = username = password = ''
    if '@' in target:
        creds, host = target.rsplit('@', 1)
        if '/' in creds:
            domain, creds = creds.split('/', 1)
        if ':' in creds:
            username, password = creds.split(':', 1)
        else:
            username = creds
    else:
        host = target
    return domain, username, password, host


def main():
    print("RPCDump standalone — no impacket required")
    print("=" * 50)

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Dumps remote RPC endpoints via epmapper (standalone, no impacket)."
    )
    parser.add_argument(
        'target', action='store',
        help='[[domain/]username[:password]@]<targetName or address>'
    )
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts',    action='store_true', help='Add timestamp to logging output')

    conn = parser.add_argument_group('connection')
    conn.add_argument(
        '-target-ip', action='store', metavar='ip address',
        help='IP address of target (useful when target is a NetBIOS name)'
    )
    conn.add_argument(
        '-port', choices=['135'], nargs='?', default='135',
        metavar='destination port',
        help='Destination port (only 135/ncacn_ip_tcp supported in standalone mode)'
    )
    conn.add_argument(
        '-timeout', action='store', type=int, default=10, metavar='seconds',
        help='TCP connection timeout (default: 10)'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    init_logger(add_ts=options.ts, debug=options.debug)

    domain, username, password, remote_name = parse_target(options.target)

    if password == '' and username != '':
        password = getpass.getpass("Password: ")

    remote_host = options.target_ip if options.target_ip else remote_name

    dumper = RPCDump(port=int(options.port), timeout=options.timeout)
    dumper.dump(remote_name, remote_host)


if __name__ == '__main__':
    main()
