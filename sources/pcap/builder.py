from model.pcap_model import PcapModel

def build_model(filename):
    return PcapModel(filename).load()
