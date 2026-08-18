"""Analysis and result objects for PCAP input."""
from __future__ import annotations

from dataclasses import dataclass

from pcap_model import PcapModel


@dataclass
class PcapIssue:
    severity: str
    rule: str
    ied: str
    location: str
    description: str

    def as_tuple(self):
        return self.severity, self.rule, self.ied, self.location, self.description


def analyze_pcap(model: PcapModel) -> list[PcapIssue]:
    issues: list[PcapIssue] = []
    if model.packet_count == 0:
        issues.append(PcapIssue("ERROR", "PCAP-001", "", "PCAP", "No packets were decoded from the capture."))
        return issues

    issues.append(PcapIssue("INFO", "PCAP-INFO", "", "PCAP", f"Decoded {model.packet_count} packet(s)."))

    if model.mms_count == 0:
        issues.append(PcapIssue("WARNING", "PCAP-MMS-001", "", "MMS", "No TCP/102 MMS traffic was detected."))
        return issues

    issues.append(PcapIssue("INFO", "PCAP-MMS-001", "", "MMS", f"Detected {model.mms_count} TCP/102 packet(s)."))

    if model.mms_messages:
        counts = {}
        for msg in model.mms_messages:
            counts[msg.service] = counts.get(msg.service, 0) + 1
        summary = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items()))
        issues.append(PcapIssue("INFO", "PCAP-MMS-DEC-001", "", "MMS decoder", f"Decoded {len(model.mms_messages)} MMS PDU(s): {summary}."))
        for msg in model.mms_messages:
            location = f"{msg.direction}, invoke={msg.invoke_id}"
            issues.append(PcapIssue("INFO", "PCAP-MMS-DEC-002", "", location, f"Decoded MMS service: {msg.service}."))
    else:
        issues.append(PcapIssue("WARNING", "PCAP-MMS-DEC-001", "", "MMS decoder", "MMS TCP traffic was found, but no MMS PDU could be decoded from the reassembled streams."))

    if model.mms_warnings:
        for warning in model.mms_warnings:
            issues.append(PcapIssue("WARNING", "PCAP-MMS-DEC-003", "", "MMS decoder", warning))

    if model.discovery_count:
        issues.append(PcapIssue("INFO", "PCAP-DISC-001", "", "MMS discovery", f"Detected {model.discovery_count} packet(s) containing recognizable discovery markers."))
    else:
        issues.append(PcapIssue(
            "WARNING", "PCAP-DISC-001", "", "MMS discovery",
            "MMS traffic was detected, but a complete discovery sequence could not be reconstructed from this capture. "
            "Runtime compliance checks are therefore not asserted."
        ))

    if model.get_name_list:
        total_ids = sum(len(x.identifiers) for x in model.get_name_list)
        issues.append(PcapIssue(
            "INFO", "PCAP-DISC-NL-001", "", "GetNameList",
            f"Correlated {len(model.get_name_list)} GetNameList request/response pair(s), returning {total_ids} identifier(s)."
        ))
        for index, transaction in enumerate(model.get_name_list, 1):
            scope = transaction.object_scope or "unknown scope"
            obj_class = "unknown" if transaction.object_class is None else str(transaction.object_class)
            preview = ", ".join(transaction.identifiers[:20])
            if len(transaction.identifiers) > 20:
                preview += ", ..."
            issues.append(PcapIssue(
                "INFO", "PCAP-DISC-NL-002", "",
                f"GetNameList #{index}",
                f"invoke={transaction.invoke_id}, objectClass={obj_class}, scope={scope}, "
                f"continueAfter={transaction.continue_after or '-'}, moreFollows={transaction.more_follows}; "
                f"identifiers: {preview or '(none)'}"
            ))
    if model.get_variable_access_attributes:
        issues.append(PcapIssue(
            "INFO", "PCAP-DISC-VAA-001", "", "GetVariableAccessAttributes",
            f"Correlated {len(model.get_variable_access_attributes)} GetVariableAccessAttributes request/response pair(s)."
        ))
        for index, transaction in enumerate(model.get_variable_access_attributes, 1):
            attrs = transaction.attributes or {}
            type_spec = attrs.get("typeSpecification")
            type_tag = type_spec.get("tag") if isinstance(type_spec, dict) else None
            components = attrs.get("components") or []
            issues.append(PcapIssue(
                "INFO", "PCAP-DISC-VAA-002", "",
                f"GetVariableAccessAttributes #{index}",
                f"invoke={transaction.invoke_id}, object={transaction.object_name or '-'}, "
                f"mmsDeletable={attrs.get('mmsDeletable')}, typeSpecificationTag={type_tag}, "
                f"components={len(components)}"
            ))
            for component in components:
                issues.append(PcapIssue(
                    "INFO", "PCAP-DISC-DO-DA-001", "",
                    transaction.object_name or "GetVariableAccessAttributes",
                    f"Runtime component {component.get('path', '-')}: "
                    f"type={component.get('type', 'unknown')}"
                ))
    elif any(msg.service == "getVariableAccessAttributes" for msg in model.mms_messages):
        issues.append(PcapIssue(
            "WARNING", "PCAP-DISC-VAA-003", "", "GetVariableAccessAttributes",
            "GetVariableAccessAttributes MMS PDU(s) were decoded, but no request/response pair could be correlated."
        ))

    elif any(msg.service == "getNameList" for msg in model.mms_messages):
        issues.append(PcapIssue(
            "WARNING", "PCAP-DISC-NL-003", "", "GetNameList",
            "GetNameList MMS PDU(s) were decoded, but no request/response pair could be correlated. "
            "The capture may be incomplete or the transaction may span unavailable packets."
        ))

    if model.parse_warnings:
        for warning in model.parse_warnings:
            issues.append(PcapIssue("WARNING", "PCAP-PARSE-001", "", "PCAP", warning))

    issues.append(PcapIssue(
        "INFO", "PCAP-SCOPE-001", "", "Analysis scope",
        "ASN.1 BER, MMS GetNameList decoding and request/response correlation are enabled. "
        "GetVariableAccessAttributes request/response decoding is enabled, including structural DO/DA/SDI component paths. CDC semantics, report runtime checks and GOOSE runtime checks remain subsequent stages."
    ))
    return issues
