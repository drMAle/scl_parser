import struct
import tempfile
import unittest
from pathlib import Path

from analyzer import Analyzer
from model import Model, SCLModel, PcapModel


class ArchitectureTests(unittest.TestCase):
    def test_model_inheritance(self):
        self.assertTrue(issubclass(SCLModel, Model))
        self.assertTrue(issubclass(PcapModel, Model))
        self.assertEqual(SCLModel.source_type, "scl")
        self.assertEqual(PcapModel.source_type, "pcap")

    def test_incomplete_pcap_is_error(self):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = 6
        ip[12:16] = bytes([10, 0, 0, 1])
        ip[16:20] = bytes([10, 0, 0, 2])
        ip[2:4] = struct.pack("!H", 40)
        tcp = bytearray(20)
        tcp[0:2] = struct.pack("!H", 12345)
        tcp[2:4] = struct.pack("!H", 102)
        tcp[12] = 0x50
        raw = eth + bytes(ip) + bytes(tcp)
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packet = struct.pack("<IIII", 1, 0, len(raw), len(raw)) + raw
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "incomplete.pcap"
            path.write_bytes(header + packet)
            model = PcapModel(path).load()
            issues = Analyzer(model).run()
            rules = {i.rule_id for i in issues}
            self.assertIn("PCAP-DISC-001", rules)


if __name__ == "__main__":
    unittest.main()
