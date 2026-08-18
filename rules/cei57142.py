"""Adapter between CEI 57-142 validator and the GUI Analyzer."""
from cei57142 import validate_cei57142


def run_cei57142_rules(analyzer):
    for finding in validate_cei57142(analyzer.model):
        analyzer.add_issue(
            finding.get("severity", "INFO"),
            finding.get("rule_id", "CEI57142"),
            _ied_from_location(finding.get("location", "")),
            finding.get("location", ""),
            _format_message(finding),
        )


def _ied_from_location(location):
    if not location:
        return ""
    for part in str(location).split("/"):
        if part.startswith("IED="):
            return part[4:]
    return ""


def _format_message(finding):
    clause = finding.get("clause")
    category = finding.get("category")
    desc = finding.get("description", "")
    prefix = []
    if clause:
        prefix.append(f"Clause {clause}")
    if category:
        prefix.append(str(category))
    return f"[{', '.join(prefix)}] {desc}" if prefix else desc
