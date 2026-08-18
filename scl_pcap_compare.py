"""Comparison of an SCL configuration model with a PCAP observation model."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pcap_model import PcapModel
from scl_parser import SCLModel


@dataclass
class CompareIssue:
    severity: str
    rule: str
    ied: str
    location: str
    description: str

    def as_tuple(self):
        return self.severity, self.rule, self.ied, self.location, self.description


def compare_scl_pcap(scl_filename: str | Path, pcap_model: PcapModel) -> list[CompareIssue]:
    issues: list[CompareIssue] = []
    try:
        model = SCLModel(scl_filename)
        model.load()
    except Exception as exc:
        return [CompareIssue("ERROR", "CMP-SCL-001", "", "SCL", f"Unable to load SCL: {exc}")]

    issues.append(CompareIssue(
        "INFO", "CMP-001", "", "Comparison",
        "SCL model loaded successfully."
    ))

    if pcap_model.mms_count == 0:
        issues.append(CompareIssue(
            "WARNING", "CMP-PCAP-001", "", "PCAP",
            "No MMS TCP/102 traffic was found; SCL/PCAP alignment cannot be established."
        ))
        return issues

    issues.append(CompareIssue(
        "INFO", "CMP-PCAP-001", "", "PCAP",
        f"PCAP contains {pcap_model.mms_count} MMS packet(s)."
    ))
    if pcap_model.mms_messages:
        services = sorted({msg.service for msg in pcap_model.mms_messages})
        issues.append(CompareIssue(
            "INFO", "CMP-MMS-001", "", "MMS",
            "Decoded MMS services: " + ", ".join(services) + "."
        ))

    # At this stage the packet model does not yet expose a complete MMS object
    # hierarchy. Do not manufacture MATCH/MISSING findings: classify them as
    # not yet verifiable instead of generating false positives.
    issues.append(CompareIssue(
        "INFO", "CMP-SCOPE-001", "", "Alignment",
        "Logical-node/Data-object alignment is not asserted yet: ASN.1/MMS PDU decoding is enabled, but the complete IEC 61850 directory reconstruction and SCL correlation are the next sub-stage."
    ))

    return issues
