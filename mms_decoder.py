"""Dependency-free BER/ASN.1 and MMS decoder for IEC 61850 discovery traffic.

This module intentionally implements the parts of BER and MMS needed to turn a
TCP/102 capture into an IEC 61850 runtime model. It is not a general ASN.1
compiler. Unknown MMS services are retained as raw BER nodes and reported as
unsupported rather than guessed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


class BERDecodeError(ValueError):
    pass


@dataclass
class BERNode:
    tag_class: int
    constructed: bool
    tag: int
    value: bytes = b""
    children: list["BERNode"] = field(default_factory=list)
    offset: int = 0
    end: int = 0

    @property
    def is_context(self) -> bool:
        return self.tag_class == 2

    @property
    def text(self) -> str:
        return decode_text(self.value)


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise BERDecodeError("Missing BER length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0:
        raise BERDecodeError("Indefinite BER length is not supported")
    if count > 4 or pos + count > len(data):
        raise BERDecodeError("Invalid BER long-form length")
    length = int.from_bytes(data[pos:pos + count], "big")
    return length, pos + count


def parse_ber(data: bytes, offset: int = 0, end: int | None = None) -> list[BERNode]:
    end = len(data) if end is None else end
    nodes: list[BERNode] = []
    pos = offset
    while pos < end:
        start = pos
        if pos >= len(data):
            break
        first = data[pos]
        pos += 1
        tag_class = first >> 6
        constructed = bool(first & 0x20)
        tag = first & 0x1F
        if tag == 0x1F:
            tag = 0
            while True:
                if pos >= end:
                    raise BERDecodeError("Truncated high-tag-number")
                b = data[pos]
                pos += 1
                tag = (tag << 7) | (b & 0x7F)
                if not b & 0x80:
                    break
        length, pos = _read_length(data, pos)
        value_start = pos
        value_end = pos + length
        if value_end > end:
            raise BERDecodeError("BER value exceeds enclosing buffer")
        value = data[value_start:value_end]
        children = parse_ber(data, value_start, value_end) if constructed and value else []
        nodes.append(BERNode(tag_class, constructed, tag, value, children, start, value_end))
        pos = value_end
    return nodes


def decode_integer(node: BERNode) -> int | None:
    if not node.value:
        return 0
    return int.from_bytes(node.value, "big", signed=bool(node.value[0] & 0x80))


def decode_text(data: bytes) -> str:
    for enc in ("utf-8", "ascii", "latin-1"):
        try:
            text = data.decode(enc)
            if all(ch == "\t" or ch == "\r" or ch == "\n" or ord(ch) >= 32 for ch in text):
                return text
        except UnicodeDecodeError:
            pass
    return ""


def walk(node: BERNode) -> Iterable[BERNode]:
    yield node
    for child in node.children:
        yield from walk(child)


def context(node: BERNode, tag: int) -> list[BERNode]:
    return [n for n in node.children if n.tag_class == 2 and n.tag == tag]


def first_context(node: BERNode, tag: int) -> BERNode | None:
    items = context(node, tag)
    return items[0] if items else None


def _all_printable_strings(node: BERNode) -> list[str]:
    out: list[str] = []
    for n in walk(node):
        if not n.constructed:
            text = decode_text(n.value).strip("\x00")
            if 1 <= len(text) <= 512 and all(ord(c) >= 32 for c in text) and any(c.isalpha() or c in "_.$-/" for c in text):
                out.append(text)
    return out


# MMS service numbers from ISO 9506-1, encoded as context-specific choices
# inside ConfirmedServiceRequest/Response. The decoder is deliberately
# conservative and only maps services whose structure we consume.
REQUEST_SERVICES = {
    1: "getNameList",
    4: "identify",
    6: "getVariableAccessAttributes",
    11: "getNamedVariableListAttributes",
    12: "getNamedVariableListAttributes",  # tolerated vendor/edition variant
}
RESPONSE_SERVICES = {
    1: "getNameList",
    4: "identify",
    6: "getVariableAccessAttributes",
    11: "getNamedVariableListAttributes",
}


@dataclass
class MMSMessage:
    direction: str
    service: str
    invoke_id: int | None
    root: BERNode
    strings: list[str] = field(default_factory=list)
    raw: bytes = b""
    identifiers: list[str] = field(default_factory=list)
    object_class: int | None = None
    object_scope: str | None = None
    continue_after: str | None = None
    more_follows: bool | None = None
    object_name: str | None = None
    variable_attributes: dict | None = None


@dataclass
class MMSDecodeResult:
    messages: list[MMSMessage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _find_mms_pdu(nodes: list[BERNode]) -> BERNode | None:
    """Locate an MMS confirmed/unconfirmed PDU below ACSE/presentation.

    ACSE itself also uses context-specific tags, so selecting the first [0] or
    [1] node is unsafe. Confirmed request/response PDUs have a distinctive
    shape: [0]/[1] containing an invoke-id [0] and a confirmed-service [1].
    """
    candidates: list[BERNode] = []
    for root in nodes:
        for n in walk(root):
            if n.tag_class != 2 or not n.constructed:
                continue
            if n.tag not in (0, 1, 2, 3, 8, 9, 10, 11, 12, 13):
                continue
            c0 = first_context(n, 0)
            c1 = first_context(n, 1)
            if n.tag in (0, 1) and c0 is not None and c1 is not None and c1.constructed:
                candidates.append(n)
            elif n.tag in (2, 3, 8, 9, 10, 11, 12, 13):
                candidates.append(n)
    if candidates:
        # Prefer confirmed request/response over generic unconfirmed nodes.
        candidates.sort(key=lambda n: (0 if n.tag in (0, 1) else 1, n.offset))
        return candidates[0]
    return None


def strip_tpkt_cotp(data: bytes) -> bytes:
    """Return the bytes after TPKT/COTP when recognizable."""
    if len(data) >= 4 and data[:2] == b"\x03\x00":
        total = int.from_bytes(data[2:4], "big")
        data = data[:total] if total <= len(data) else data
        if len(data) < 7:
            return b""
        # TPKT(4) + COTP header. COTP length is first byte after TPKT.
        cotp_len = data[4]
        start = 5 + cotp_len
        if start <= len(data):
            return data[start:]
    return data


def extract_mms_pdus(stream: bytes) -> list[bytes]:
    """Extract TPKT-framed application payloads from a reassembled TCP stream."""
    pdus: list[bytes] = []
    pos = 0
    while pos + 4 <= len(stream):
        if stream[pos:pos + 2] != b"\x03\x00":
            # Search forward; captures can begin mid-stream.
            nxt = stream.find(b"\x03\x00", pos + 1)
            if nxt < 0:
                break
            pos = nxt
        total = int.from_bytes(stream[pos + 2:pos + 4], "big")
        if total < 7 or pos + total > len(stream):
            break
        payload = strip_tpkt_cotp(stream[pos:pos + total])
        if payload:
            pdus.append(payload)
        pos += total
    return pdus


def _primitive_strings(node: BERNode) -> list[str]:
    """Return printable primitive strings below *node*.

    MMS Identifier is encoded as an IA5String.  We deliberately accept other
    printable string encodings as well because captures from different MMS
    stacks/editions can use a different universal string tag while retaining
    the same textual value.
    """
    out: list[str] = []
    for n in walk(node):
        if n.constructed:
            continue
        text = decode_text(n.value).strip("\x00")
        if 1 <= len(text) <= 255 and all(ord(c) >= 32 for c in text):
            out.append(text)
    return out


def _decode_get_name_list_request(service_node: BERNode) -> tuple[int | None, str | None, str | None]:
    """Decode the GetNameList request enough to identify its scope.

    The service is a context-specific [1] sequence containing objectClass [0]
    and objectScope [1].  Scope is represented by a choice; for the discovery
    use case we expose the choice name rather than guessing an IEC 61850 path.
    """
    object_class = None
    object_scope = None
    oc = first_context(service_node, 0)
    if oc is not None:
        # ObjectClass is an INTEGER under an IMPLICIT context-specific tag.
        if oc.value:
            try:
                object_class = decode_integer(oc)
            except Exception:
                object_class = None
    scope = first_context(service_node, 1)
    if scope is not None:
        if scope.children:
            child = scope.children[0]
            if child.tag_class == 2:
                object_scope = f"[{child.tag}]"
        elif scope.value:
            object_scope = "[1]"
    cont = first_context(service_node, 2)
    continue_after = decode_text(cont.value) if cont is not None and not cont.constructed else None
    return object_class, object_scope, continue_after


def _decode_get_name_list_response(service_node: BERNode) -> tuple[list[str], bool | None]:
    """Extract the Identifier sequence from a GetNameList response."""
    # GetNameList-Response ::= SEQUENCE {
    #   listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier,
    #   moreFollows [1] IMPLICIT BOOLEAN }
    identifiers_node = first_context(service_node, 0)
    identifiers = _primitive_strings(identifiers_node) if identifiers_node is not None else []
    more = first_context(service_node, 1)
    more_follows = None
    if more is not None and more.value:
        more_follows = more.value[0] != 0
    return identifiers, more_follows



def _decode_identifier_node(node: BERNode) -> str | None:
    if node is None:
        return None
    if not node.constructed:
        text = decode_text(node.value).strip("\x00")
        return text or None
    for child in node.children:
        text = _decode_identifier_node(child)
        if text:
            return text
    return None


def _decode_object_name(service_node: BERNode) -> str | None:
    """Decode the MMS ObjectName CHOICE used by IEC 61850.

    IEC 61850 commonly uses the domain-specific form [2] containing
    domainID + itemID.  We preserve the generic CHOICE for other forms.
    """
    for tag in (0, 1, 2, 3):
        choice = first_context(service_node, tag)
        if choice is None:
            continue
        if tag == 2 and choice.children:
            vals = []
            for child in choice.children:
                text = _decode_identifier_node(child)
                if text:
                    vals.append(text)
            if len(vals) >= 2:
                return f"{vals[0]}/{vals[1]}"
            if vals:
                return vals[0]
        text = _decode_identifier_node(choice)
        if text:
            return text
        return f"[{tag}]"
    return None


MMS_TYPE_NAMES = {
    0: "array",
    1: "structure",
    2: "boolean",
    3: "bit-string",
    4: "integer",
    5: "unsigned",
    6: "floating-point",
    7: "octet-string",
    8: "visible-string",
    9: "generalized-time",
    10: "binary-time",
    11: "bcd",
    12: "obj-id",
    13: "mms-string",
}


def _type_node_summary(node: BERNode) -> dict:
    """Return a structural MMS TypeSpecification summary.

    For MMS structures, component names and their nested TypeSpecifications
    are retained explicitly. This is the information needed to reconstruct
    IEC 61850 DO/DA/SDI trees from GetVariableAccessAttributes responses.
    """
    summary = {
        "tag": node.tag,
        "class": node.tag_class,
        "constructed": node.constructed,
        "type": MMS_TYPE_NAMES.get(node.tag, f"context[{node.tag}]"),
    }
    if not node.constructed:
        if node.tag_class == 0:
            summary["value"] = decode_integer(node) if node.tag == 2 else decode_text(node.value)
        return summary

    # MMS TypeSpecification structure [1] contains a SEQUENCE OF Components.
    # Each component is a SEQUENCE { componentName [0] Identifier,
    # componentType [1] TypeSpecification }. Some captures expose the
    # componentType choice through one additional context-specific wrapper;
    # the unwrapping below makes the decoder tolerant of both encodings.
    if node.tag_class == 2 and node.tag == 1:
        components = []
        for comp in node.children:
            if comp.tag_class != 0 or comp.tag != 16:
                continue
            name_node = first_context(comp, 0)
            type_node = first_context(comp, 1)
            if type_node is not None and type_node.constructed and len(type_node.children) == 1:
                nested = type_node.children[0]
                if nested.tag_class == 2:
                    type_node = nested
            name = _decode_identifier_node(name_node) if name_node is not None else None
            item = {"name": name, "typeSpecification": _type_node_summary(type_node) if type_node is not None else None}
            components.append(item)
        if components:
            summary["components"] = components
            return summary

    # A TypeSpecification wrapper can similarly contain one context-specific
    # choice. Unwrap it when it is clearly not a structure component list.
    if node.tag_class == 2 and node.constructed and len(node.children) == 1:
        child = node.children[0]
        if child.tag_class == 2 and child.tag == node.tag:
            return _type_node_summary(child)

    children = []
    for child in node.children:
        item = _type_node_summary(child)
        text = _decode_identifier_node(child)
        if text and not child.constructed:
            item["identifier"] = text
        children.append(item)
    summary["children"] = children
    return summary


def _flatten_type_components(type_spec: dict | None, prefix: str = "") -> list[dict]:
    """Flatten MMS TypeSpecification components into IEC 61850-style paths."""
    if not type_spec:
        return []
    out: list[dict] = []
    for component in type_spec.get("components", []):
        name = component.get("name")
        if not name:
            continue
        path = f"{prefix}.{name}" if prefix else name
        child_type = component.get("typeSpecification") or {}
        out.append({
            "name": name,
            "path": path,
            "type": child_type.get("type", "unknown"),
            "tag": child_type.get("tag"),
            "class": child_type.get("class"),
            "constructed": child_type.get("constructed", False),
        })
        out.extend(_flatten_type_components(child_type, path))
    return out


def _decode_get_variable_access_attributes_request(service_node: BERNode) -> str | None:
    # GetVariableAccessAttributes-Request ::= ObjectName
    return _decode_object_name(service_node)


def _decode_get_variable_access_attributes_response(service_node: BERNode) -> dict:
    """Decode the response structurally without guessing IEC 61850 CDC semantics.

    Response ::= SEQUENCE { mmsDeletable [0] IMPLICIT BOOLEAN,
                            typeSpecification [1] TypeSpecification }
    """
    deletable = None
    d = first_context(service_node, 0)
    if d is not None and d.value:
        deletable = d.value[0] != 0
    type_spec = first_context(service_node, 1)
    summary = _type_node_summary(type_spec) if type_spec is not None else None
    return {"mmsDeletable": deletable, "typeSpecification": summary, "components": _flatten_type_components(summary)}


def decode_mms_pdu(payload: bytes, direction: str = "unknown") -> MMSMessage | None:
    # Presentation/ACSE are BER, but the MMS PDU can be found recursively.
    nodes = parse_ber(payload)
    pdu = _find_mms_pdu(nodes)
    if pdu is None:
        return None

    service = "unknown"
    invoke_id = None
    identifiers: list[str] = []
    object_class = None
    object_scope = None
    continue_after = None
    more_follows = None
    object_name = None
    variable_attributes = None
    if pdu.tag == 0:  # confirmed-request-pdu
        # invokeID is normally [0], confirmedServiceRequest [1].
        inv = first_context(pdu, 0)
        if inv is not None and inv.value:
            invoke_id = decode_integer(inv)
        csr = first_context(pdu, 1)
        if csr is not None:
            for child in csr.children:
                if child.tag_class == 2 and child.tag in REQUEST_SERVICES:
                    service = REQUEST_SERVICES[child.tag]
                    if service == "getNameList":
                        object_class, object_scope, continue_after = _decode_get_name_list_request(child)
                    elif service == "getVariableAccessAttributes":
                        object_name = _decode_get_variable_access_attributes_request(child)
                    break
    elif pdu.tag == 1:  # confirmed-response-pdu
        inv = first_context(pdu, 0)
        if inv is not None and inv.value:
            invoke_id = decode_integer(inv)
        csr = first_context(pdu, 1)
        if csr is not None:
            for child in csr.children:
                if child.tag_class == 2 and child.tag in RESPONSE_SERVICES:
                    service = RESPONSE_SERVICES[child.tag]
                    if service == "getNameList":
                        identifiers, more_follows = _decode_get_name_list_response(child)
                    elif service == "getVariableAccessAttributes":
                        variable_attributes = _decode_get_variable_access_attributes_response(child)
                    break
    elif pdu.tag == 2:
        service = "confirmed-error"
    elif pdu.tag == 3:
        service = "unconfirmed-write"
    elif pdu.tag == 8:
        service = "informationReport"
    elif pdu.tag == 9:
        service = "unconfirmed-pdu"

    return MMSMessage(
        direction, service, invoke_id, pdu, _all_printable_strings(pdu), payload,
        identifiers=identifiers, object_class=object_class, object_scope=object_scope,
        continue_after=continue_after, more_follows=more_follows,
        object_name=object_name, variable_attributes=variable_attributes
    )


def decode_stream(stream: bytes, direction: str = "unknown") -> MMSDecodeResult:
    result = MMSDecodeResult()
    for payload in extract_mms_pdus(stream):
        try:
            msg = decode_mms_pdu(payload, direction)
            if msg:
                result.messages.append(msg)
        except BERDecodeError as exc:
            result.warnings.append(f"BER/MMS decode error: {exc}")
    return result
