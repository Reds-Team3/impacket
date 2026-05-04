#!/usr/bin/env python3
"""
Standalone DCE/RPC endpoint mapper dumper.
No impacket dependency — all protocol logic implemented from scratch.
Supports port 135 (ncacn_ip_tcp) only.
"""

from __future__ import print_function

import sys
import socket
import struct
import uuid as _uuid_mod
import argparse
import logging
import getpass

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def init_logger(add_ts=False, debug=False):
    level = logging.DEBUG if debug else logging.INFO
    fmt = ('%(asctime)s ' if add_ts else '') + '%(levelname)s: %(message)s'
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
REPRESENTATION_LE   = 0x10

EPMAPPER_UUID        = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
EPMAPPER_VERSION     = 3
EPMAPPER_VERSION_MIN = 0

NDR_UUID    = '8a885d04-1ceb-11c9-9fe8-08002b104860'
NDR_VERSION = 2

EPT_LOOKUP  = 2
MAX_ENTRIES = 500
ANNOTATION_SIZE = 64


# ---------------------------------------------------------------------------
# UUID helpers
# ---------------------------------------------------------------------------

def pack_uuid_bytes(uuid_str):
    return _uuid_mod.UUID(uuid_str).bytes_le


def unpack_uuid_bytes(data, offset=0):
    raw = bytes(data[offset:offset + 16])
    if len(raw) != 16:
        raise ValueError("Need 16 bytes for UUID, got %d (offset=%d buf_len=%d)"
                         % (len(raw), offset, len(data)))
    return str(_uuid_mod.UUID(bytes_le=raw))


# ---------------------------------------------------------------------------
# PDU building
# ---------------------------------------------------------------------------

def build_common_header(ptype, frag_len, call_id, flags=PFC_FIRST_FRAG | PFC_LAST_FRAG):
    return bytes([
        MSRPC_VERSION, MSRPC_MINOR_VERSION, ptype, flags,
        REPRESENTATION_LE, 0x00, 0x00, 0x00,
    ]) + struct.pack('<HHI', frag_len, 0, call_id)


def build_bind_pdu(call_id=1):
    epm_if   = pack_uuid_bytes(EPMAPPER_UUID) + struct.pack('<HH', EPMAPPER_VERSION, EPMAPPER_VERSION_MIN)
    ndr_xfer = pack_uuid_bytes(NDR_UUID)      + struct.pack('<HH', NDR_VERSION, 0)
    # p_cont_list: num_contexts(2) + reserved(2) + ctx_id(2) + num_xfer(2) + if(20) + xfer(20)
    p_cont = struct.pack('<HH', 1, 0) + struct.pack('<HH', 0, 1) + epm_if + ndr_xfer
    # BIND body: max_xmit(2) + max_recv(2) + assoc_group(4) + p_cont
    body = struct.pack('<HHI', 4280, 4280, 0) + p_cont
    frag_len = 16 + len(body)
    return build_common_header(MSRPC_BIND, frag_len, call_id) + body


def parse_bind_ack(data):
    if len(data) < 16:
        raise ValueError("BIND_ACK too short")
    ptype = data[2]
    if ptype == MSRPC_FAULT:
        status = struct.unpack_from('<I', data, 16)[0] if len(data) >= 20 else 0
        raise RuntimeError("BIND fault 0x%08x" % status)
    if ptype != MSRPC_BIND_ACK:
        raise RuntimeError("Expected BIND_ACK(12) got ptype=%d" % ptype)
    if len(data) < 26:
        raise ValueError("BIND_ACK too short for sec_addr")
    sec_addr_len = struct.unpack_from('<H', data, 24)[0]
    offset = (26 + sec_addr_len + 3) & ~3   # 4-byte align
    if offset + 4 > len(data):
        raise ValueError("BIND_ACK too short for p_results (offset=%d len=%d)" % (offset, len(data)))
    num_results = struct.unpack_from('<H', data, offset)[0]
    offset += 4
    for _ in range(num_results):
        if offset + 2 > len(data):
            break
        result = struct.unpack_from('<H', data, offset)[0]
        if result == 0:
            return True
        offset += 24
    raise RuntimeError("All bind contexts rejected")


def build_request_pdu(call_id, opnum, stub_data):
    # alloc_hint(4) + p_context_id(2) + opnum(2)
    body = struct.pack('<IHH', len(stub_data), 0, opnum) + stub_data
    frag_len = 16 + len(body)
    return build_common_header(MSRPC_REQUEST, frag_len, call_id) + body


# ---------------------------------------------------------------------------
# ept_lookup NDR encoding
# ---------------------------------------------------------------------------

def build_ept_lookup_request(entry_handle_bytes=None):
    """
    NDR encoding of ept_lookup() in-parameters.

    Wire layout (all LE):
      inquiry_type  : UINT32 = 0  (RPC_C_EP_ALL_ELTS)
      object_ptr    : UINT32 = 0  (NULL unique pointer)
      if_id_ptr     : UINT32 = 0  (NULL unique pointer)
      vers_option   : UINT32 = 0
      entry_handle  : 20 bytes    (context handle, zeros = start of enumeration)
      max_ents      : UINT32
    """
    if entry_handle_bytes is None:
        entry_handle_bytes = b'\x00' * 20
    return (
        struct.pack('<I', 0)              # inquiry_type
        + struct.pack('<I', 0)            # *object  = NULL
        + struct.pack('<I', 0)            # *if_id   = NULL
        + struct.pack('<I', 0)            # vers_option
        + bytes(entry_handle_bytes)       # entry_handle (20 bytes)
        + struct.pack('<I', MAX_ENTRIES)  # max_ents
    )


# ---------------------------------------------------------------------------
# ept_lookup NDR response decoding
#
# ept_entry_t on the wire (NDR, per MS-RPCE / C706):
#   object        16 bytes  (UUID bytes_le)
#   tower_ptr      4 bytes  (unique pointer referent ID, 0 = NULL)
#   annotation    64 bytes  (fixed char[64], NOT a conformant string)
#
# The array is conformant: max_count (4 bytes) precedes the elements.
# After all elements, deferred tower blobs appear in order (one per
# non-NULL tower_ptr).
#
# twr_t is a conformant struct (C706 Appendix L / MS-RPCE):
#   typedef struct {
#     unsigned32 tower_length;
#     [size_is(tower_length)] byte tower_octet_string[];
#   } twr_t;
#
# Because tower_length is the size_is attribute, it IS the NDR max_count,
# so it appears exactly ONCE on the wire before the floor data:
#   tower_length  4 bytes   (= NDR max_count for the conformant array)
#   floor_data    tower_length bytes
#
# There is NO second length field. Reading two uint32s was wrong.
#
# After all deferred blobs:
#   num_ents   4 bytes  (actual entries returned this call)
#   status     4 bytes
# ---------------------------------------------------------------------------

def _align4(n):
    return (n + 3) & ~3


def parse_ept_lookup_response(stub):
    offset = 0

    def read(n, what=''):
        nonlocal offset
        if offset + n > len(stub):
            raise ValueError("stub too short for %s: need offset+%d=%d, have %d"
                             % (what, n, offset + n, len(stub)))
        chunk = stub[offset:offset + n]
        offset += n
        return chunk

    def read_u32(what=''):
        return struct.unpack('<I', read(4, what))[0]

    # entry_handle (20 bytes)
    entry_handle = read(20, 'entry_handle')

    # num_ents
    num_ents = read_u32('num_ents')

    # conformant array max_count
    max_count = read_u32('max_count')

    logging.debug("parse_ept_lookup_response: num_ents=%d max_count=%d stub_len=%d"
                  % (num_ents, max_count, len(stub)))

    entries = []
    for i in range(max_count):
        obj_uuid      = unpack_uuid_bytes(read(16, 'obj_uuid[%d]' % i))
        tower_ref     = read_u32('tower_ref[%d]' % i)
        raw_ann       = read(ANNOTATION_SIZE, 'annotation[%d]' % i)
        annotation    = raw_ann.rstrip(b'\x00').decode('utf-8', errors='replace')
        entries.append({
            'object_uuid':    obj_uuid,
            'annotation':     annotation,
            'tower_referent': tower_ref,
            'tower_floors':   [],
        })

    # deferred tower blobs
    for entry in entries:
        if entry['tower_referent'] == 0:
            continue
        # twr_t conformant struct: tower_length(4) + tower_octet_string(tower_length)
        # tower_length IS the NDR max_count — appears exactly once, not twice.
        tower_len = read_u32('tower_len')
        logging.debug("  tower blob: len=%d at offset=%d" % (tower_len, offset))
        tower_bytes = read(tower_len, 'tower_bytes')
        entry['tower_floors'] = parse_tower(tower_bytes)

    # trailing status
    status = 0
    if offset + 4 <= len(stub):
        status = struct.unpack_from('<I', stub, offset)[0]
    logging.debug("  status=0x%08x remaining_bytes=%d" % (status, len(stub) - offset - 4))

    return entry_handle, entries[:num_ents], status


# ---------------------------------------------------------------------------
# Tower parsing
# ---------------------------------------------------------------------------

def parse_tower(data):
    """
    DCE/RPC protocol tower → list of floor dicts.

    Floor LHS layout:
      Floor 0+1: [1-byte proto_id=0x0d][16-byte UUID][2-byte ver][2-byte ver_minor]
      Floor 2+:  [1-byte proto_id][optional protocol-specific data]
    """
    if len(data) < 2:
        return []
    num_floors = struct.unpack_from('<H', data, 0)[0]
    offset = 2
    floors = []
    for _ in range(num_floors):
        if offset + 2 > len(data):
            break
        lhs_len = struct.unpack_from('<H', data, offset)[0]; offset += 2
        if offset + lhs_len > len(data):
            break
        lhs = data[offset:offset + lhs_len]; offset += lhs_len

        if offset + 2 > len(data):
            break
        rhs_len = struct.unpack_from('<H', data, offset)[0]; offset += 2
        if offset + rhs_len > len(data):
            break
        rhs = data[offset:offset + rhs_len]; offset += rhs_len

        floors.append({
            'lhs':         lhs,
            'rhs':         rhs,
            'protocol_id': lhs[0] if lhs else 0,
        })
    return floors


def get_uuid_from_floor0(floors):
    """Floor 0 LHS: [proto_id(1)][UUID(16)][ver(2)][ver_minor(2)] — UUID starts at byte 1."""
    if not floors:
        return None
    lhs = floors[0]['lhs']
    if len(lhs) < 17:
        return None
    try:
        return unpack_uuid_bytes(lhs, 1)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Known UUID tables
# ---------------------------------------------------------------------------

# Floor 2 protocol_id → transport string
TRANSPORT_PROTO = {
    0x07: 'ncacn_ip_tcp',
    0x08: 'ncadg_ip_udp',
    0x09: 'ncacn_nb_nb',
    0x0c: 'ncacn_spx',
    0x0d: 'ncacn_ip_tcp',
    0x0e: 'ncadg_ip_udp',
    0x0f: 'ncacn_np',
    0x10: 'ncacn_np',
    0x11: 'ncalrpc',
    0x1f: 'ncacn_http',
    0x04: 'ncacn_dnet_nsp',
}

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


# ---------------------------------------------------------------------------
# Binding string formatter
# ---------------------------------------------------------------------------

def floor_to_binding_string(floors):
    if not floors:
        return 'N/A'
    try:
        proto_id = floors[2]['protocol_id'] if len(floors) > 2 else 0
        proto    = TRANSPORT_PROTO.get(proto_id, 'unknown(0x%02x)' % proto_id)
        parts = []
        for fl in floors[3:]:
            rhs = fl['rhs']
            pid = fl['protocol_id']
            if pid in (0x07, 0x0d):      # TCP port (big-endian)
                if len(rhs) >= 2:
                    parts.append('[%d]' % struct.unpack('>H', rhs[:2])[0])
            elif pid in (0x08, 0x0e):    # UDP port
                if len(rhs) >= 2:
                    parts.append('[%d]' % struct.unpack('>H', rhs[:2])[0])
            elif pid == 0x09:            # IPv4 address
                if len(rhs) == 4:
                    parts.append('%d.%d.%d.%d' % tuple(rhs))
            elif pid in (0x0f, 0x10, 0x11, 0x1f):  # named pipe / lrpc / http
                s = rhs.rstrip(b'\x00').decode('utf-8', errors='replace')
                if s:
                    parts.append('[%s]' % s)
            else:
                s = rhs.rstrip(b'\x00').decode('utf-8', errors='replace')
                if s and all(c.isprintable() for c in s):
                    parts.append(s)
        return (proto + ':' + ''.join(parts)) if parts else proto
    except Exception as ex:
        return 'parse_error(%s)' % ex


# ---------------------------------------------------------------------------
# TCP transport with raw PDU reassembly
# ---------------------------------------------------------------------------

class TCPTransport:
    def __init__(self, host, port=135, timeout=10):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self._sock   = None

    def connect(self):
        logging.debug("TCP connect → %s:%d" % (self.host, self.port))
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        # once connected, use a generous per-read timeout
        self._sock.settimeout(self.timeout)

    def send(self, data):
        logging.debug("send %d bytes" % len(data))
        self._sock.sendall(data)

    def recv_pdu(self):
        """
        Read and reassemble one complete MSRPC PDU from potentially multiple fragments.

        Each fragment is a self-contained PDU with its own 16-byte common header.
        The 16-byte common header layout:
          [0]  rpc_vers
          [1]  rpc_vers_minor
          [2]  PTYPE
          [3]  pfc_flags   ← PFC_FIRST_FRAG=0x01, PFC_LAST_FRAG=0x02
          [4:8] packed_drep
          [8:10] frag_length   ← total bytes in THIS fragment including header
          [10:12] auth_length
          [12:16] call_id

        For RESPONSE PDUs, after the 16-byte common header there is an 8-byte
        response header: alloc_hint(4) + p_context_id(2) + cancel_count(1) + reserved(1).
        Stub data begins at byte 24 of the first fragment.

        Continuation fragments have the same 16+8 = 24-byte prefix before their
        stub chunk. We keep the first fragment's full PDU (header+response_hdr+stub)
        and append only the stub portions from subsequent fragments so that the
        caller can always find stub data at pdu[24:].
        """
        # Read first fragment
        hdr = self._recv_n(16)
        logging.debug("recv hdr: %s" % hdr.hex())
        frag_len = struct.unpack_from('<H', hdr, 8)[0]
        if frag_len < 16:
            raise ValueError("Malformed PDU: frag_len=%d" % frag_len)
        body = self._recv_n(frag_len - 16)
        pdu  = hdr + body

        # flags from the CURRENT fragment (not the accumulated pdu)
        cur_flags = hdr[3]

        # Reassemble continuation fragments until PFC_LAST_FRAG is set
        while not (cur_flags & PFC_LAST_FRAG):
            logging.debug("fragment not last (flags=0x%02x), reading next" % cur_flags)
            fhdr  = self._recv_n(16)
            logging.debug("cont frag hdr: %s" % fhdr.hex())
            fflen = struct.unpack_from('<H', fhdr, 8)[0]
            if fflen < 16:
                raise ValueError("Malformed continuation fragment: frag_len=%d" % fflen)
            fbody     = self._recv_n(fflen - 16)
            cur_flags = fhdr[3]
            # Each continuation fragment has a 24-byte prefix (16 common + 8 response hdr).
            # We only want the stub chunk; fbody already has 16 bytes stripped,
            # so skip the remaining 8-byte response sub-header.
            stub_chunk = fbody[8:]
            pdu += stub_chunk
            logging.debug("  appended %d stub bytes (flags=0x%02x)" % (len(stub_chunk), cur_flags))

        logging.debug("recv_pdu complete: %d total bytes, ptype=%d" % (len(pdu), pdu[2]))
        return pdu

    def _recv_n(self, n):
        if n == 0:
            return b''
        buf = b''
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except socket.timeout:
                raise TimeoutError(
                    "Timed out waiting for %d bytes (got %d so far). "
                    "Server may have dropped the connection — check firewall rules for port 135 "
                    "beyond initial TCP handshake (some firewalls allow SYN but drop data)."
                    % (n, len(buf))
                )
            if not chunk:
                raise EOFError("Server closed connection after %d/%d bytes" % (len(buf), n))
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
        logging.debug("Sending BIND PDU")
        self._transport.send(build_bind_pdu(call_id=self._call_id))
        logging.debug("Waiting for BIND_ACK")
        resp = self._transport.recv_pdu()
        parse_bind_ack(resp)
        logging.debug("BIND_ACK accepted")
        self._call_id += 1

    def lookup_all(self):
        all_entries  = []
        entry_handle = b'\x00' * 20

        while True:
            stub = build_ept_lookup_request(entry_handle)
            req  = build_request_pdu(self._call_id, EPT_LOOKUP, stub)
            self._call_id += 1
            logging.debug("Sending ept_lookup REQUEST (call_id=%d)" % (self._call_id - 1))
            self._transport.send(req)
            resp = self._transport.recv_pdu()

            ptype = resp[2]
            if ptype == MSRPC_FAULT:
                status = struct.unpack_from('<I', resp, 24)[0] if len(resp) >= 28 else 0
                raise RuntimeError("RPC_FAULT: 0x%08x" % status)
            if ptype != MSRPC_RESPONSE:
                raise RuntimeError("Unexpected PDU type %d (expected RESPONSE=2)" % ptype)

            # Stub data: common header(16) + response header(alloc_hint(4)+ctx_id(2)+cancel_count(1)+reserved(1)) = 24
            stub_data = resp[24:]
            entry_handle, entries, status = parse_ept_lookup_response(stub_data)
            logging.debug("ept_lookup returned %d entries, status=0x%08x" % (len(entries), status))
            all_entries.extend(entries)

            # EPT_S_NOT_REGISTERED (0x16c9a0d6) or any non-zero = done
            if status != 0 or len(entries) == 0:
                break

        return all_entries

    def disconnect(self):
        self._transport.disconnect()


# ---------------------------------------------------------------------------
# RPCDump
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
            logging.critical("Connection failed to %s:%d — %s" % (remote_host, self._port, e))
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

        endpoints = {}
        for entry in entries:
            floors  = entry.get('tower_floors', [])
            if_uuid = get_uuid_from_floor0(floors) or entry.get('object_uuid', 'unknown')
            key     = if_uuid.lower()

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
        description="Dumps remote RPC endpoints via epmapper (standalone, no impacket)."
    )
    parser.add_argument('target', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug',   action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts',      action='store_true', help='Add timestamp to logging output')
    parser.add_argument('-target-ip', metavar='ip', help='IP address of target')
    parser.add_argument('-port',    choices=['135'], default='135', help='Destination port (135 only)')
    parser.add_argument('-timeout', type=int, default=10, metavar='seconds', help='TCP timeout (default 10)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    init_logger(add_ts=options.ts, debug=options.debug)

    _, username, password, remote_name = parse_target(options.target)
    if password == '' and username != '':
        password = getpass.getpass("Password: ")

    remote_host = options.target_ip if options.target_ip else remote_name

    RPCDump(port=int(options.port), timeout=options.timeout).dump(remote_name, remote_host)


if __name__ == '__main__':
    main()
