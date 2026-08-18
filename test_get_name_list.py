from mms_decoder import decode_mms_pdu


def ctx(tag, value, constructed=True):
    return bytes([0xA0 + tag if constructed else 0x80 + tag, len(value)]) + value


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


# Minimal Confirmed-Request / GetNameList
get_name_service = ctx(1, ctx(0, b"\x02", False) + ctx(1, b"", True), True)
request_service = ctx(1, get_name_service, True)
request = ctx(0, ctx(0, b"\x01", False) + request_service, True)

m = decode_mms_pdu(request, "10.0.0.1:50000 -> 10.0.0.2:102")
assert m is not None
assert m.service == "getNameList"
assert m.invoke_id == 1
assert m.object_class == 2

# Minimal Confirmed-Response / GetNameList with two identifiers.
ids = tlv(0x16, b"LD_Plant") + tlv(0x16, b"LD_Aux")
get_name_response = ctx(1, ctx(0, ids, True) + ctx(1, b"\x00", False), True)
response_service = ctx(1, get_name_response, True)
response = ctx(1, ctx(0, b"\x01", False) + response_service, True)

m = decode_mms_pdu(response, "10.0.0.2:102 -> 10.0.0.1:50000")
assert m is not None
assert m.service == "getNameList"
assert m.invoke_id == 1
assert m.identifiers == ["LD_Plant", "LD_Aux"]
assert m.more_follows is False

print("GetNameList tests: PASS")
