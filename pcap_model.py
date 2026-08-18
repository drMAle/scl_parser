"""PCAP inspection model for IEC 61850 discovery/runtime analysis.

The first implementation deliberately keeps packet decoding dependency-free. It
reads classic PCAP and PCAPNG files and identifies Ethernet/IPv4/TCP/UDP flows,
with special attention to MMS (TCP/102) traffic. Full ASN.1/MMS discovery
reconstruction is kept behind this model so it can be extended without changing
the GUI.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass
class PcapPacket:
    number: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    payload: bytes = b""
    tcp_seq: int | None = None


@dataclass
class RuntimeDataAttribute:
    name: str
    path: str
    type: str
    tag: int | None = None
    constructed: bool = False


@dataclass
class RuntimeDataObject:
    object_name: str
    data_objects: list[str] = field(default_factory=list)
    data_attributes: list[RuntimeDataAttribute] = field(default_factory=list)
    mms_deletable: bool | None = None


@dataclass
class GetVariableAccessAttributesTransaction:
    request_direction: str
    response_direction: str
    invoke_id: int | None
    object_name: str | None
    attributes: dict = field(default_factory=dict)
    data_object: RuntimeDataObject | None = None


@dataclass
class GetNameListTransaction:
    request_direction: str
    response_direction: str
    invoke_id: int | None
    object_class: int | None
    object_scope: str | None
    continue_after: str | None
    identifiers: list[str] = field(default_factory=list)
    more_follows: bool | None = None


@dataclass
class PcapModel:
    filename: Path
    packets: list[PcapPacket] = field(default_factory=list)
    mms_packets: list[PcapPacket] = field(default_factory=list)
    discovery_packets: list[PcapPacket] = field(default_factory=list)
    printable_tokens: set[str] = field(default_factory=set)
    parse_warnings: list[str] = field(default_factory=list)
    mms_messages: list = field(default_factory=list)
    mms_warnings: list[str] = field(default_factory=list)
    get_name_list: list[GetNameListTransaction] = field(default_factory=list)
    get_variable_access_attributes: list[GetVariableAccessAttributesTransaction] = field(default_factory=list)
    runtime_data_objects: dict[str, RuntimeDataObject] = field(default_factory=dict)

    def load(self) -> None:
        self.packets = []
        self.mms_packets = []
        self.discovery_packets = []
        self.printable_tokens = set()
        self.parse_warnings = []
        self.mms_messages = []
        self.mms_warnings = []
        self.get_name_list = []
        self.get_variable_access_attributes = []
        self.runtime_data_objects = {}

        data = Path(self.filename).read_bytes()
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            self._parse_pcap(data)
        elif data[:4] in (b"\x0a\x0d\x0d\x0a",):
            self._parse_pcapng(data)
        else:
            raise ValueError("Unsupported capture format: expected PCAP or PCAPNG")

        self.mms_packets = [
            p for p in self.packets
            if p.protocol == "TCP" and (p.src_port == 102 or p.dst_port == 102)
        ]
        self.discovery_packets = [
            p for p in self.mms_packets
            if _looks_like_mms_discovery(p.payload)
        ]
        for packet in self.mms_packets:
            for token in _extract_tokens(packet.payload):
                self.printable_tokens.add(token)

        self._decode_mms_streams()

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def mms_count(self) -> int:
        return len(self.mms_packets)

    @property
    def discovery_count(self) -> int:
        return len(self.discovery_packets)

    def _decode_mms_streams(self) -> None:
        from mms_decoder import decode_stream

        flows: dict[tuple[str, int, str, int], list[PcapPacket]] = {}
        for packet in self.mms_packets:
            if packet.src_port is None or packet.dst_port is None or packet.tcp_seq is None:
                continue
            key = (packet.src, packet.src_port, packet.dst, packet.dst_port)
            flows.setdefault(key, []).append(packet)

        for key, packets in flows.items():
            packets.sort(key=lambda p: (p.tcp_seq if p.tcp_seq is not None else 0, p.number))
            stream = b"".join(p.payload for p in packets)
            direction = f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}"
            result = decode_stream(stream, direction)
            self.mms_messages.extend(result.messages)
            self.mms_warnings.extend(result.warnings)

        self._correlate_get_name_list()
        self._correlate_get_variable_access_attributes()

    def _correlate_get_name_list(self) -> None:
        """Correlate GetNameList requests and responses by invoke ID/direction."""
        self.get_name_list = []
        self.get_variable_access_attributes = []
        requests = [m for m in self.mms_messages
                    if m.service == "getNameList" and m.identifiers == []
                    and m.direction.split(" -> ")[0].rsplit(":", 1)[-1] != "102"]
        responses = [m for m in self.mms_messages
                     if m.service == "getNameList" and m.identifiers
                     and m.direction.split(" -> ")[0].rsplit(":", 1)[-1] == "102"]
        used: set[int] = set()
        for req in requests:
            for idx, resp in enumerate(responses):
                if idx in used:
                    continue
                if req.invoke_id != resp.invoke_id:
                    continue
                req_src, req_dst = req.direction.split(" -> ")
                resp_src, resp_dst = resp.direction.split(" -> ")
                if req_src != resp_dst or req_dst != resp_src:
                    continue
                self.get_name_list.append(GetNameListTransaction(
                    req.direction, resp.direction, req.invoke_id,
                    req.object_class, req.object_scope, req.continue_after,
                    resp.identifiers, resp.more_follows
                ))
                used.add(idx)
                break

    def _correlate_get_variable_access_attributes(self) -> None:
        """Correlate GetVariableAccessAttributes requests/responses by invoke ID."""
        self.get_variable_access_attributes = []
        requests = [m for m in self.mms_messages
                    if m.service == "getVariableAccessAttributes" and m.object_name]
        responses = [m for m in self.mms_messages
                     if m.service == "getVariableAccessAttributes" and m.variable_attributes is not None]
        used: set[int] = set()
        for req in requests:
            for idx, resp in enumerate(responses):
                if idx in used or req.invoke_id != resp.invoke_id:
                    continue
                req_src, req_dst = req.direction.split(" -> ")
                resp_src, resp_dst = resp.direction.split(" -> ")
                if req_src != resp_dst or req_dst != resp_src:
                    continue
                attrs = resp.variable_attributes or {}
                components = attrs.get("components", [])
                runtime_do = RuntimeDataObject(
                    object_name=req.object_name or "",
                    data_attributes=[
                        RuntimeDataAttribute(
                            name=item.get("name", ""),
                            path=item.get("path", ""),
                            type=item.get("type", "unknown"),
                            tag=item.get("tag"),
                            constructed=item.get("constructed", False),
                        )
                        for item in components if item.get("name")
                    ],
                    mms_deletable=attrs.get("mmsDeletable"),
                )
                # The requested MMS object is the IEC 61850 Data Object.
                # Keep the complete dotted component paths as DA/SDI evidence.
                self.runtime_data_objects[runtime_do.object_name] = runtime_do
                self.get_variable_access_attributes.append(GetVariableAccessAttributesTransaction(
                    req.direction, resp.direction, req.invoke_id,
                    req.object_name, attrs, runtime_do
                ))
                used.add(idx)
                break

    def _parse_pcap(self, data: bytes) -> None:
        magic = data[:4]
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        if len(data) < 24:
            raise ValueError("PCAP header is truncated")
        _, _, _, _, _, _, network = struct.unpack(endian + "IHHIIII", data[:24])
        offset = 24
        number = 0
        while offset + 16 <= len(data):
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                endian + "IIII", data[offset:offset + 16]
            )
            offset += 16
            payload = data[offset:offset + incl_len]
            offset += incl_len
            if len(payload) != incl_len:
                self.parse_warnings.append("Truncated packet at end of PCAP")
                break
            number += 1
            packet = _decode_link_packet(number, ts_sec + ts_frac / 1_000_000.0, payload, network)
            if packet:
                self.packets.append(packet)

    def _parse_pcapng(self, data: bytes) -> None:
        # Minimal Enhanced Packet Block reader. Link-layer type is taken from
        # the first Interface Description Block (normally Ethernet = 1).
        offset = 0
        interfaces: dict[int, int] = {}
        number = 0
        while offset + 12 <= len(data):
            block_type, block_len = struct.unpack("<II", data[offset:offset + 8])
            if block_len < 12 or offset + block_len > len(data):
                self.parse_warnings.append("Invalid/truncated PCAPNG block")
                break
            block = data[offset:offset + block_len]
            if block_type == 0x00000001 and len(block) >= 20:
                link_type = struct.unpack("<H", block[8:10])[0]
                interfaces[len(interfaces)] = link_type
            elif block_type == 0x00000006 and len(block) >= 32:
                interface_id, ts_hi, ts_lo, cap_len = struct.unpack("<IIII", block[8:24])
                packet_start = 28
                packet_end = packet_start + cap_len
                raw = block[packet_start:packet_end]
                ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                number += 1
                packet = _decode_link_packet(number, ts, raw, interfaces.get(interface_id, 1))
                if packet:
                    self.packets.append(packet)
            offset += block_len


def _decode_link_packet(number: int, timestamp: float, raw: bytes, network: int) -> PcapPacket | None:
    # LINKTYPE_ETHERNET = 1; LINKTYPE_RAW = 101; LINKTYPE_LINUX_SLL = 113.
    if network == 1:
        if len(raw) < 14:
            return None
        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype == 0x0800:
            return _decode_ipv4(number, timestamp, raw[14:])
        return PcapPacket(number, timestamp, "", "", f"ETHERTYPE 0x{ethertype:04x}", payload=raw[14:])
    if network == 101:
        return _decode_ipv4(number, timestamp, raw)
    if network == 113 and len(raw) >= 16:
        proto = struct.unpack("!H", raw[14:16])[0]
        if proto == 0x0800:
            return _decode_ipv4(number, timestamp, raw[16:])
    return PcapPacket(number, timestamp, "", "", "LINK", payload=raw)


def _decode_ipv4(number: int, timestamp: float, raw: bytes) -> PcapPacket | None:
    if len(raw) < 20:
        return None
    version_ihl = raw[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(raw) < ihl:
        return None
    protocol = raw[9]
    src = ".".join(str(x) for x in raw[12:16])
    dst = ".".join(str(x) for x in raw[16:20])
    transport = raw[ihl:]
    if protocol == 6 and len(transport) >= 20:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        data_offset = ((transport[12] >> 4) & 0xF) * 4
        payload = transport[data_offset:] if len(transport) >= data_offset else b""
        seq = struct.unpack("!I", transport[4:8])[0]
        return PcapPacket(number, timestamp, src, dst, "TCP", src_port, dst_port, payload, seq)
    if protocol == 17 and len(transport) >= 8:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        return PcapPacket(number, timestamp, src, dst, "UDP", src_port, dst_port, transport[8:])
    return PcapPacket(number, timestamp, src, dst, str(protocol), payload=transport)


def _extract_tokens(payload: bytes) -> Iterable[str]:
    # Useful as an initial discovery aid; MMS strings are commonly UTF-8/ASCII
    # but not all identifiers are necessarily encoded this way.
    text = payload.decode("utf-8", errors="ignore")
    for match in re.finditer(r"[A-Za-z_][A-Za-z0-9_.:/-]{2,127}", text):
        yield match.group(0)


def _looks_like_mms_discovery(payload: bytes) -> bool:
    text = payload.decode("utf-8", errors="ignore").lower()
    markers = (
        "getserverdirectory",
        "getlogicaldevicedirectory",
        "getlogicalnodedirectory",
        "getdatadirectory",
        "getdatasetdirectory",
        "getnamedvariablelistattributes",
        "read",
    )
    return any(marker in text for marker in markers)
