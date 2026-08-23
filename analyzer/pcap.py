"""Validation of PCAP discovery evidence.

A PCAP is an observation source. This module never completes the model from
an SCL file and never treats missing packets as harmless. A required discovery
stage that is absent is an ERROR in the supplied test evidence.
"""
from .result import Issue


REQUIRED_DISCOVERY_STAGES = (
    "getServerDirectory",
    "getLogicalNodeDirectory",
    "getDataDirectory",
    "getVariableAccessAttributes",
    "getDataSetDirectory",
)


def analyze_pcap(model):
    issues = []

    def add(severity, rule, location, description):
        issues.append(Issue(severity, rule, "", location, description))

    if model.packet_count == 0:
        add("ERROR", "PCAP-001", "PCAP", "No packets were decoded from the capture.")
        return issues

    add("INFO", "PCAP-INFO", "PCAP", f"Decoded {model.packet_count} packet(s).")

    if model.mms_count == 0:
        add("ERROR", "PCAP-MMS-001", "MMS", "No TCP/102 MMS traffic was detected.")
        return issues

    add("INFO", "PCAP-MMS-001", "MMS", f"Detected {model.mms_count} TCP/102 packet(s).")

    if not model.mms_messages:
        add("ERROR", "PCAP-MMS-DEC-001", "MMS decoder",
            "MMS TCP traffic was found, but no MMS PDU could be decoded from the reassembled streams.")
    else:
        counts = {}
        for message in model.mms_messages:
            counts[message.service] = counts.get(message.service, 0) + 1
        add("INFO", "PCAP-MMS-DEC-001", "MMS decoder",
            f"Decoded {len(model.mms_messages)} MMS PDU(s): " +
            ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) + ".")

    for warning in model.mms_warnings:
        add("WARNING", "PCAP-MMS-DEC-003", "MMS decoder", warning)

    evidence = getattr(model, "discovery_evidence", {})
    for stage in REQUIRED_DISCOVERY_STAGES:
        if not evidence.get(stage, False):
            add("ERROR", "PCAP-DISC-001", "MMS discovery",
                f"Required discovery stage '{stage}' was not observed/correlated in the capture.")
        else:
            add("INFO", "PCAP-DISC-002", stage, "Discovery evidence observed and correlated.")

    if getattr(model, "parse_warnings", None):
        for warning in model.parse_warnings:
            add("ERROR", "PCAP-PARSE-001", "PCAP", warning)

    # A decoded server identity is useful evidence, but it is not an IED name.
    identities = [m.server_identity for m in model.mms_messages if m.server_identity]
    if identities:
        ident = identities[-1]
        add("INFO", "PCAP-ID-001", "MMS Identify",
            f"Server identity observed: vendor={ident.get('vendor','')!r}, model={ident.get('model','')!r}, revision={ident.get('revision','')!r}.")
    else:
        add("WARNING", "PCAP-ID-001", "MMS Identify",
            "MMS Identify response was not observed; the capture does not provide server identity metadata.")

    return issues
