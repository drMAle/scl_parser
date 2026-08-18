from mms_decoder import decode_mms_pdu


def ctx(tag, value, constructed=True):
    return bytes([0xA0 + tag if constructed else 0x80 + tag, len(value)]) + value


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


def ident(text):
    return tlv(0x16, text.encode("ascii"))

# Confirmed-Request / GetVariableAccessAttributes.
# ObjectName = domain-specific [2] { domainID, itemID }.
object_name = ctx(2, ident("LD_Plant") + ident("MMXU1.TotW"), True)
vaa_service = ctx(6, object_name, True)
request_service = ctx(1, vaa_service, True)
request = ctx(0, ctx(0, b"\x01", False) + request_service, True)

m = decode_mms_pdu(request, "10.0.0.1:50000 -> 10.0.0.2:102")
assert m is not None
assert m.service == "getVariableAccessAttributes"
assert m.invoke_id == 1
assert m.object_name == "LD_Plant/MMXU1.TotW"

# Confirmed-Response / GetVariableAccessAttributes.
# mmsDeletable=false, typeSpecification=[1] { [9] integer } (minimal structural test).
type_spec = ctx(1, ctx(9, b"\x02", False), True)
vaa_response = ctx(6, ctx(0, b"\x00", False) + ctx(1, type_spec, True), True)
response_service = ctx(1, vaa_response, True)
response = ctx(1, ctx(0, b"\x01", False) + response_service, True)

m = decode_mms_pdu(response, "10.0.0.2:102 -> 10.0.0.1:50000")
assert m is not None
assert m.service == "getVariableAccessAttributes"
assert m.invoke_id == 1
assert m.variable_attributes["mmsDeletable"] is False
assert m.variable_attributes["typeSpecification"]["tag"] == 1

print("GetVariableAccessAttributes tests: PASS")
