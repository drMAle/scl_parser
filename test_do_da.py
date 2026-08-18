from mms_decoder import decode_mms_pdu


def ctx(tag, value, constructed=True):
    return bytes([0xA0 + tag if constructed else 0x80 + tag, len(value)]) + value


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


def ident(text):
    return tlv(0x16, text.encode("ascii"))


def seq(value):
    return tlv(0x30, value)


def component(name, type_node):
    return seq(ctx(0, ident(name), True) + ctx(1, type_node, True))

# Structure { f : floating-point, q : structure { i : integer } }
f_type = ctx(6, b"", False)
i_type = ctx(4, b"", False)
q_struct = ctx(1, component("i", i_type), True)
root_struct = ctx(1, component("f", f_type) + component("q", q_struct), True)
vaa_service = ctx(6, ctx(0, b"\x00", False) + ctx(1, root_struct, True), True)
response_service = ctx(1, vaa_service, True)
response = ctx(1, ctx(0, b"\x01", False) + response_service, True)

m = decode_mms_pdu(response, "10.0.0.2:102 -> 10.0.0.1:50000")
assert m is not None
components = m.variable_attributes["components"]
paths = [x["path"] for x in components]
assert "f" in paths
assert "q" in paths
assert "q.i" in paths
assert m.variable_attributes["typeSpecification"]["type"] == "structure"
print("DO/DA type reconstruction tests: PASS")
