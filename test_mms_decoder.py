from mms_decoder import decode_mms_pdu, decode_stream


def test_confirmed_get_name_list():
    pdu = bytes.fromhex("a00a800101a105a1038101ff")
    msg = decode_mms_pdu(pdu, "client")
    assert msg is not None
    assert msg.service == "getNameList"
    assert msg.invoke_id == 1


def test_tpkt_stream():
    pdu = bytes.fromhex("a00a800101a105a1038101ff")
    tpkt = b"\x03\x00" + (len(pdu) + 7).to_bytes(2, "big") + b"\x02\xf0\x80" + pdu
    result = decode_stream(tpkt, "client")
    assert len(result.messages) == 1
    assert result.messages[0].service == "getNameList"


if __name__ == "__main__":
    test_confirmed_get_name_list()
    test_tpkt_stream()
    print("MMS decoder tests: PASS")
