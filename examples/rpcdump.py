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

# Packet types
MSRPC_BIND          = 11
MSRPC_BIND_ACK      = 12
MSRPC_REQUEST       = 0
MSRPC_RESPONSE      = 2
MSRPC_FAULT         = 3

# Flags
PFC_FIRST_FRAG      = 0x01
PFC_LAST_FRAG       = 0x02

# Representation labels (little-endian ASCII)
REPRESENTATION_LE   = 0x10   # little-endian, ASCII, IEEE float

# EPM interface UUID and version
EPM_UUID     = '1d55b526-c137-46c5-ab79-638f0ff517d5'  # Not real epmapper —
# The real endpoint mapper UUID:
EPMAPPER_UUID        = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
EPMAPPER_VERSION     = 3
EPMAPPER_VERSION_MIN = 0

# NDR transfer syntax
NDR_UUID    = '8a885d04-1ceb-11c9-9fe8-08002b104860'
NDR_VERSION = 2

# EPM operation numbers
EPT_LOOKUP  = 2   # ept_lookup

# EPT_LOOKUP inquiry types
RPC_C_EP_ALL_ELTS = 0

# Max entries to request per lookup call
MAX_ENTRIES = 500


# ---------------------------------------------------------------------------
# Struct helpers
# ---------------------------------------------------------------------------

def pack_uuid_bytes(uuid_str):
    """
    Convert a UUID string like 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    to the 16-byte wire representation used by DCE/RPC (mixed-endian).
    Fields 1-3 are little-endian; fields 4-5 are big-endian.
    """
    u = _uuid_mod.UUID(uuid_str)
    return u.bytes_le   # Python's bytes_le matches DCE wire format


def unpack_uuid_bytes(data, offset=0):
    """
    Unpack 16 bytes of DCE UUID (bytes_le) into a UUID string.
    """
    raw = data[offset:offset + 16]
    u = _uuid_mod.UUID(bytes_le=raw)
    return str(u)


# ---------------------------------------------------------------------------
# DCE/RPC PDU framing
# ---------------------------------------------------------------------------

def build_common_header(ptype, frag_len, call_id, flags=PFC_FIRST_FRAG | PFC_LAST_FRAG):
    """
    Build the 16-byte DCE/RPC common header.

    Offset  Size  Field
    0       1     rpc_vers (5)
    1       1     rpc_vers_minor (0)
    2       1     PTYPE
    3       1     pfc_flags
    4       4     packed_drep
    8       2     frag_length
    10      2     auth_length (0)
    12      4     call_id
    """
    # Manual packing — little-endian, ASCII, IEEE float
    header = bytes([
        MSRPC_VERSION,
        MSRPC_MINOR_VERSION,
        ptype,
        flags,
        REPRESENTATION_LE, 0x00, 0x00, 0x00,   # packed_drep (4 bytes)
    ]) + struct.pack('<HHI', frag_len, 0, call_id)
    return header


def build_bind_pdu(call_id=1):
    """
    Build MSRPC BIND PDU to bind to the EPM interface with NDR transfer syntax.
    """
    # p_context_elem: 1 context
    ctx_id       = 0
    num_xfer     = 1

    epm_uuid_b   = pack_uuid_bytes(EPMAPPER_UUID)
    ndr_uuid_b   = pack_uuid_bytes(NDR_UUID)

    # p_syntax_id (interface): uuid(16) + ver_major(2) + ver_minor(2)
    if_id  = epm_uuid_b + struct.pack('<HH', EPMAPPER_VERSION, EPMAPPER_VERSION_MIN)
    # transfer syntax
    xfer   = ndr_uuid_b + struct.pack('<HH', NDR_VERSION, 0)

    p_context = struct.pack('<HH', ctx_id, num_xfer) + if_id + xfer

    # p_context_elem header: num_contexts(2) + reserved(2)
    p_context_elem = struct.pack('<HH', 1, 0) + p_context

    # BIND-specific fields
    max_xmit_frag = 4280
    max_recv_frag = 4280
    assoc_group   = 0

    bind_body = struct.pack('<HHI', max_xmit_frag, max_recv_frag, assoc_group) + p_context_elem

    frag_len = 16 + len(bind_body)
    header   = build_common_header(MSRPC_BIND, frag_len, call_id)
    return header + bind_body


def parse_bind_ack(data):
    """
    Parse MSRPC BIND_ACK. Returns True if at least one context was accepted.
    Raises on failure.
    """
    if len(data) < 16:
        raise ValueError("BIND_ACK too short")
    ptype = data[2]
    if ptype == MSRPC_FAULT:
        status = struct.unpack_from('<I', data, 16)[0]
        raise RuntimeError("BIND fault, status=0x%08x" % status)
    if ptype != MSRPC_BIND_ACK:
        raise RuntimeError("Expected BIND_ACK (12), got %d" % ptype)
    # p_results start at offset 26 (secondary_addr_len at 24 is 2 bytes, variable)
    # secondary_addr_len is at offset 24
    sec_addr_len = struct.unpack_from('<H', data, 24)[0]
    # skip secondary_addr + alignment to 4-byte boundary
    offset = 26 + sec_addr_len
    # align to 4
    offset = (offset + 3) & ~3
    # num_results (2) + reserved (2)
    num_results = struct.unpack_from('<H', data, offset)[0]
    offset += 4
    # Each result: result(2) + reason(2) + transfer_syntax(20)
    for i in range(num_results):
        result = struct.unpack_from('<H', data, offset)[0]
        if result == 0:
            return True
        offset += 24
    raise RuntimeError("All p_context items rejected in BIND_ACK")


# ---------------------------------------------------------------------------
# NDR encoding helpers for ept_lookup
# ---------------------------------------------------------------------------

def ndr_long(val):
    return struct.pack('<I', val)


def ndr_uuid(uuid_str):
    return pack_uuid_bytes(uuid_str)


def ndr_rpc_if_id(uuid_str, ver_major=0, ver_minor=0):
    return ndr_uuid(uuid_str) + struct.pack('<HH', ver_major, ver_minor)


def build_ept_lookup_request(entry_handle_bytes=None):
    """
    Build NDR-encoded ept_lookup request body.

    ept_lookup(
        [in]  unsigned32           inquiry_type,    // RPC_C_EP_ALL_ELTS = 0
        [in]  p_uuid_vector_t      *object,         // NULL
        [in]  rpc_if_id_p_t        interface_id,    // NULL
        [in]  unsigned32           vers_option,     // 0
        [in,out] ept_lookup_handle_t *entry_handle, // context handle
        [in]  unsigned32           max_ents,
        [out] unsigned32           *num_ents,
        [out] ept_entry_t          entries[],
        [out] error_status_t       *status
    )
    """
    # inquiry_type = 0 (RPC_C_EP_ALL_ELTS)
    inquiry_type = ndr_long(0)

    # *object = NULL pointer (referent=0)
    object_ptr = ndr_long(0)

    # *interface_id = NULL pointer
    if_id_ptr = ndr_long(0)

    # vers_option = 0
    vers_option = ndr_long(0)

    # entry_handle: 20-byte context handle (all zeros to start)
    if entry_handle_bytes is None:
        entry_handle_bytes = b'\x00' * 20
    entry_handle = entry_handle_bytes

    # max_ents
    max_ents = ndr_long(MAX_ENTRIES)

    body = inquiry_type + object_ptr + if_id_ptr + vers_option + entry_handle + max_ents
    return body


def build_request_pdu(call_id, opnum, stub_data):
    """
    Build MSRPC REQUEST PDU.
    """
    # REQUEST-specific header (after common 16-byte header):
    # alloc_hint(4) + p_context_id(2) + opnum(2)
    req_header = struct.pack('<IHH', len(stub_data), 0, opnum)
    body = req_header + stub_data
    frag_len = 16 + len(body)
    hdr = build_common_header(MSRPC_REQUEST, frag_len, call_id)
    return hdr + body


# ---------------------------------------------------------------------------
# NDR response parsing
# ---------------------------------------------------------------------------

def _align4(offset):
    return (offset + 3) & ~3


def parse_ept_lookup_response(stub):
    """
    Parse the NDR stub data of an ept_lookup response.

    Returns (entry_handle_bytes, entries, status)
    where entries is a list of dicts with keys:
        annotation, object_uuid, tower_floors
    """
    offset = 0

    # entry_handle (20 bytes context handle)
    entry_handle = stub[offset:offset + 20]
    offset += 20

    # num_ents (unsigned32)
    if offset + 4 > len(stub):
        raise ValueError("Stub too short for num_ents")
    num_ents = struct.unpack_from('<I', stub, offset)[0]
    offset += 4

    # entries array — conformant array: max_count first
    if offset + 4 > len(stub):
        raise ValueError("Stub too short for max_count")
    max_count = struct.unpack_from('<I', stub, offset)[0]
    offset += 4

    entries = []

    for i in range(max_count):
        entry = {}

        # object (UUID, 16 bytes)
        entry['object_uuid'] = unpack_uuid_bytes(stub, offset)
        offset += 16

        # annotation: conformant/varying string (4+4+4 + chars)
        # Encoded as: max_count(4) + offset(4) + actual_count(4) + chars(actual_count)
        if offset + 12 > len(stub):
            break
        ann_max   = struct.unpack_from('<I', stub, offset)[0]; offset += 4
        ann_off   = struct.unpack_from('<I', stub, offset)[0]; offset += 4
        ann_count = struct.unpack_from('<I', stub, offset)[0]; offset += 4
        raw_ann = stub[offset:offset + ann_count]
        # strip null terminator
        try:
            entry['annotation'] = raw_ann.rstrip(b'\x00').decode('utf-8', errors='replace')
        except Exception:
            entry['annotation'] = ''
        offset += ann_count
        # 4-byte align
        offset = _align4(offset)

        # tower
        # tower_p_t is a unique pointer (4-byte referent ID)
        referent = struct.unpack_from('<I', stub, offset)[0]; offset += 4
        if referent != 0:
            # tower: length(4) + length(4) + tower_octet_string (length bytes)
            tlen1 = struct.unpack_from('<I', stub, offset)[0]; offset += 4
            tlen2 = struct.unpack_from('<I', stub, offset)[0]; offset += 4
            tower_bytes = stub[offset:offset + tlen2]; offset += tlen2
            offset = _align4(offset)
            entry['tower_floors'] = parse_tower(tower_bytes)
        else:
            entry['tower_floors'] = []

        entries.append(entry)

    # status (last 4 bytes)
    status = 0
    if offset + 4 <= len(stub):
        status = struct.unpack_from('<I', stub, offset)[0]

    return entry_handle, entries[:num_ents], status


def parse_tower(data):
    """
    Parse a DCE/RPC tower into a list of floor dicts.
    Each floor has: protocol_id, lhs (bytes), rhs (bytes), description (str)
    """
    if len(data) < 2:
        return []
    num_floors = struct.unpack_from('<H', data, 0)[0]
    offset = 2
    floors = []
    for _ in range(num_floors):
        if offset + 4 > len(data):
            break
        lhs_len = struct.unpack_from('<H', data, offset)[0]; offset += 2
        if offset + lhs_len > len(data):
            break
        lhs = data[offset:offset + lhs_len]; offset += lhs_len
        rhs_len = struct.unpack_from('<H', data, offset)[0]; offset += 2
        if offset + rhs_len > len(data):
            break
        rhs = data[offset:offset + rhs_len]; offset += rhs_len

        floor = {'lhs': lhs, 'rhs': rhs, 'protocol_id': lhs[0] if lhs else 0}
        floors.append(floor)
    return floors


# ---------------------------------------------------------------------------
# Protocol/UUID lookup tables (from impacket's epm.py KNOWN_UUIDS / KNOWN_PROTOCOLS)
# ---------------------------------------------------------------------------

KNOWN_PROTOCOLS = {
    # Floor protocol identifiers
    0x0d: 'ncacn_ip_tcp',
    0x0e: 'ncadg_ip_udp',
    0x09: 'ncacn_ip_tcp',   # also used
    0x0f: 'ncacn_nb_nb',
    0x10: 'ncacn_np',
    0x11: 'ncalrpc',
    0x1f: 'ncacn_http',
    0x04: 'ncacn_dnet_nsp',
    0x06: 'ncacn_dnet_nsp',
}

# UUID -> human-readable protocol name (subset of impacket's KNOWN_PROTOCOLS for UUIDs)
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
    '000001a0-0000-0000-c000-000000000046': 'DCOM',
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
    '6bffd098-a112-3610-9833-46c3f87e345a': 'Workstation Service',
    '45f52c28-7f9f-101a-b52b-08002b2efabe': 'WINS',
    '811109bf-a4e1-11d1-ab54-00a0c91e9b45': 'WINS',
    'bfa951d1-2f0e-11d3-bfd1-00c04fa3490a': 'WINS',
    '45f52c28-7f9f-101a-b52b-08002b2efabe': 'WINS',
    'f5cc59b4-4264-101a-8c59-08002b2f8426': 'File Replication',
    'd049b186-814f-11d1-9a3c-00c04fc9b232': 'File Replication',
    'a00c021c-2be2-11d2-b678-0000f87a8f8e': 'File Replication',
    'fc683bff-952e-11d2-8276-0000f87a8f8e': 'File Replication',
    'db6b59c4-8a94-11d2-8278-0000f87a8f8e': 'File Replication',
    '6bffd098-a112-3610-9833-46c3f87e345a': 'Workstation Service',
    'c9378ff1-16f7-11d0-a0b2-00aa0061426a': 'PAStore Engine',
}

# UUID -> executable/process name (subset)
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


# ---------------------------------------------------------------------------
# Binding string formatter
# ---------------------------------------------------------------------------

def floor_to_binding_string(floors):
    """
    Convert parsed tower floors into a human-readable binding string,
    mimicking impacket's epm.PrintStringBinding.
    """
    if not floors:
        return 'N/A'

    try:
        # Floor 0: interface UUID + version
        f0 = floors[0]
        if len(f0['lhs']) >= 19:
            if_uuid = unpack_uuid_bytes(f0['lhs'][1:17])
            ver     = struct.unpack_from('<H', f0['lhs'], 17)[0]
        else:
            if_uuid = 'N/A'
            ver     = 0

        # Floor 1: transfer syntax (NDR)
        # Floor 2: protocol identifier
        # Floor 3+: address, port, etc.

        proto_floor = floors[2] if len(floors) > 2 else None
        addr_floors = floors[3:] if len(floors) > 3 else []

        proto_id = proto_floor['protocol_id'] if proto_floor else 0
        proto    = KNOWN_PROTOCOLS.get(proto_id, 'unknown(0x%02x)' % proto_id)

        addr_parts = []
        for af in addr_floors:
            rhs = af['rhs']
            pid = af['protocol_id']
            if pid in (0x09, 0x0d):   # TCP port
                if len(rhs) >= 2:
                    port = struct.unpack('>H', rhs[:2])[0]
                    addr_parts.append(':%d' % port)
            elif pid == 0x0e:         # UDP port
                if len(rhs) >= 2:
                    port = struct.unpack('>H', rhs[:2])[0]
                    addr_parts.append(':%d' % port)
            elif pid in (0x09, 0x0f, 0x10, 0x11, 0x1f):
                if rhs:
                    try:
                        addr_parts.append('[%s]' % rhs.rstrip(b'\x00').decode('utf-8', errors='replace'))
                    except Exception:
                        pass
            else:
                if rhs:
                    try:
                        decoded = rhs.rstrip(b'\x00').decode('utf-8', errors='replace')
                        if decoded:
                            addr_parts.append(decoded)
                    except Exception:
                        pass

        return '%s%s' % (proto, ''.join(addr_parts))
    except Exception as e:
        return 'parse_error(%s)' % e


def get_uuid_from_floor0(floors):
    """Extract the interface UUID string from floor 0."""
    if not floors:
        return None
    f0 = floors[0]
    if len(f0['lhs']) >= 17:
        try:
            return unpack_uuid_bytes(f0['lhs'][1:17])
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Transport: raw TCP socket with reassembly
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
        """
        Receive exactly one MSRPC PDU, reassembling fragments if needed.
        """
        # Read at least the 16-byte common header
        header = self._recv_exactly(16)
        frag_len = struct.unpack_from('<H', header, 8)[0]
        rest     = self._recv_exactly(frag_len - 16)
        pdu      = header + rest

        # Check for multi-fragment responses
        flags = pdu[3]
        while not (flags & PFC_LAST_FRAG):
            # Read next fragment header
            next_hdr  = self._recv_exactly(16)
            next_flen = struct.unpack_from('<H', next_hdr, 8)[0]
            next_rest = self._recv_exactly(next_flen - 16)
            flags     = next_hdr[3]
            # Append stub data only (skip the 16-byte header + 8-byte request hdr of fragment)
            pdu += next_rest[8:]  # 8 = alloc_hint(4)+ctx_id(2)+opnum(2)

        return pdu

    def _recv_exactly(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("Connection closed after %d/%d bytes" % (len(buf), n))
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
        self._do_bind()

    def _do_bind(self):
        pdu = build_bind_pdu(call_id=self._call_id)
        self._transport.send(pdu)
        resp = self._transport.recv_pdu()
        parse_bind_ack(resp)
        self._call_id += 1

    def lookup_all(self):
        """
        Iteratively call ept_lookup until all entries are returned.
        Returns a flat list of entry dicts.
        """
        all_entries    = []
        entry_handle   = b'\x00' * 20
        ept_status     = 0

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
                raise RuntimeError("Unexpected PDU type %d in ept_lookup response" % ptype)

            # Stub data starts after common header (16) + response header (alloc_hint(4)+ctx_id(2)+cancel_count(1)+reserved(1)) = 24
            stub_data = resp[24:]

            entry_handle, entries, ept_status = parse_ept_lookup_response(stub_data)

            all_entries.extend(entries)

            # 0x16c9a0d6 = EPT_S_NOT_REGISTERED (no more entries)
            # 0x00000000 = success (more may follow)
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

        # Group by UUID
        endpoints = {}
        for entry in entries:
            floors   = entry.get('tower_floors', [])
            if_uuid  = get_uuid_from_floor0(floors)
            if if_uuid is None:
                if_uuid = entry.get('object_uuid', 'unknown')

            if if_uuid not in endpoints:
                endpoints[if_uuid] = {
                    'annotation': entry.get('annotation', ''),
                    'bindings':   [],
                    'exe':        KNOWN_UUID_EXES.get(if_uuid.lower(), 'N/A'),
                    'protocol':   KNOWN_UUID_PROTOCOLS.get(if_uuid.lower(), 'N/A'),
                }

            binding = floor_to_binding_string(floors)
            if binding not in endpoints[if_uuid]['bindings']:
                endpoints[if_uuid]['bindings'].append(binding)

            # Prefer non-empty annotation
            if not endpoints[if_uuid]['annotation'] and entry.get('annotation'):
                endpoints[if_uuid]['annotation'] = entry['annotation']

        for ep_uuid, ep in endpoints.items():
            print("Protocol: %s " % ep['protocol'])
            print("Provider: %s " % ep['exe'])
            print("UUID    : %s %s" % (ep_uuid, ep['annotation']))
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
    """
    Parse [[domain/]username[:password]@]<host> into (domain, username, password, host).
    """
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
