"""PCAP Report/MMS observation.

MMS is ASN.1 encoded over TCP/102. Full decoding is best delegated to
Wireshark/tshark because it depends on the negotiated MMS presentation
context. This module therefore provides two levels:
  * exact packet-level detection of MMS/TCP traffic;
  * optional tshark JSON extraction when tshark is installed.
"""
from __future__ import annotations
import json, shutil, subprocess


def tshark_available():
    return shutil.which('tshark') is not None


def analyze_reports(path):
    """Return report observations. Uses tshark when available, otherwise
    returns TCP/102 packet observations from classic PCAP."""
    if tshark_available():
        cmd = ['tshark','-r',str(path),'-T','json','-Y','mms']
        try:
            raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            packets = json.loads(raw)
            out=[]
            for p in packets:
                layers=p.get('_source',{}).get('layers',{})
                out.append({'kind':'mms','layers':layers})
            return out
        except Exception:
            pass
    try:
        from .reader import read_pcap
        out=[]
        for ts, frame in read_pcap(path):
            if len(frame) < 34: continue
            et=int.from_bytes(frame[12:14],'big'); ip=14
            if et == 0x8100:
                et=int.from_bytes(frame[16:18],'big'); ip=18
            if et != 0x0800 or len(frame) < ip+20: continue
            ihl=(frame[ip]&0x0f)*4
            if frame[ip+9] != 6: continue
            tcp=ip+ihl
            if len(frame)<tcp+4: continue
            sport=int.from_bytes(frame[tcp:tcp+2],'big'); dport=int.from_bytes(frame[tcp+2:tcp+4],'big')
            if sport == 102 or dport == 102:
                out.append({'kind':'mms-tcp-102','timestamp':ts,'src_port':sport,'dst_port':dport})
        return out
    except Exception:
        return []
