"""Dependency-free IEC 61850 GOOSE Ethernet parser."""
from __future__ import annotations
import struct

GOOSE_ETHERTYPE = 0x88B8


def _u16(b, o): return struct.unpack_from('!H', b, o)[0]
def _u32(b, o): return struct.unpack_from('!I', b, o)[0]


def _ber_len(data, offset):
    if offset >= len(data): return None, offset
    x = data[offset]; offset += 1
    if x < 0x80: return x, offset
    n = x & 0x7f
    if n == 0 or offset+n > len(data): return None, offset
    return int.from_bytes(data[offset:offset+n], 'big'), offset+n


def _tlv(data, offset):
    if offset >= len(data): return None
    tag = data[offset]; length, p = _ber_len(data, offset+1)
    if length is None or p+length > len(data): return None
    return tag, length, p, data[p:p+length], p+length


def parse_goose_frame(ts, frame):
    if len(frame) < 14: return None
    dst = ':'.join(f'{x:02x}' for x in frame[0:6])
    src = ':'.join(f'{x:02x}' for x in frame[6:12])
    et = _u16(frame, 12)
    pos = 14
    vlan = None; priority = None
    if et in (0x8100, 0x88A8):
        if len(frame) < 18: return None
        tci = _u16(frame, 14)
        priority = (tci >> 13) & 7; vlan = tci & 0x0fff; et = _u16(frame, 16); pos = 18
    if et != GOOSE_ETHERTYPE: return None
    if len(frame) < pos + 8: return None
    appid = _u16(frame, pos); length = _u16(frame, pos+2); pos += 8
    payload = frame[pos:]
    result = {'timestamp': ts, 'dst_mac': dst, 'src_mac': src, 'ethertype': et,
              'vlan_id': vlan, 'vlan_priority': priority, 'appid': appid,
              'frame_length': length}
    # GOOSE PDU is an application-specific BER structure. Extract common
    # fields by tag; this is deliberately tolerant of extension/security data.
    p = 0
    while p < len(payload):
        item = _tlv(payload, p)
        if not item: break
        tag, ln, start, value, end = item
        if tag == 0x61:
            q = start
            while q < end:
                sub = _tlv(payload, q)
                if not sub: break
                st, sl, ss, sv, se = sub
                # [0] gocbRef, [1] timeAllowedToLive, [2] datSet,
                # [3] goID, [4] t, [5] stNum, [6] sqNum, [7] test,
                # [8] confRev, [9] ndsCom, [10] numDatSetEntries
                mapping = {0:'gocb_ref', 2:'dataset', 3:'go_id', 5:'st_num',
                           6:'sq_num', 7:'test', 8:'conf_rev', 9:'nds_com',
                           10:'num_dat_set_entries'}
                key = mapping.get(st)
                if key:
                    if st in (5,6,8,10): result[key] = int.from_bytes(sv, 'big')
                    elif st in (7,9): result[key] = bool(sv[-1]) if sv else False
                    else: result[key] = sv.decode('utf-8', 'replace')
                q = se
        p = end
    return result


def read_goose(path):
    from .reader import read_pcap
    for ts, frame in read_pcap(path):
        item = parse_goose_frame(ts, frame)
        if item is not None:
            yield item
