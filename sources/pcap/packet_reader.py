"""Low-level packet reader compatibility layer."""
from model.pcap_model import PcapPacket

def read_capture(filename):
    from model.pcap_model import PcapModel
    model=PcapModel(filename).load()
    return model.packets
