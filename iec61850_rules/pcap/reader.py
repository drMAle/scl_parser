"""Small dependency-free PCAP/PCAPNG reader.

PCAPNG support is intentionally delegated to tshark when available. Classic
PCAP Ethernet frames are parsed directly for GOOSE, so GOOSE analysis has no
third-party Python dependency.
"""
from __future__ import annotations
import struct


def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] == b'\x0a\x0d\x0d\x0a':
        raise ValueError('PCAPNG requires tshark for this analyzer.')
    if len(data) < 24:
        raise ValueError('Invalid or truncated PCAP file.')
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1': endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4': endian = '>'
    elif magic == b'\x4d\x3c\xb2\xa1': endian = '<'
    elif magic == b'\xa1\xb2\x3c\x4d': endian = '>'
    else: raise ValueError('Unsupported PCAP byte order/magic.')
    linktype = struct.unpack_from(endian + 'I', data, 20)[0]
    if linktype != 1:
        raise ValueError(f'Unsupported link type {linktype}; Ethernet (1) is required.')
    offset = 24
    while offset + 16 <= len(data):
        sec, usec, incl, orig = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        if offset + incl > len(data): break
        yield sec + usec / 1_000_000.0, data[offset:offset+incl]
        offset += incl
