"""Adapter between the data-driven CEI 0-16 profile and Analyzer."""
from cei016_profile import analyze_cei016


def run_cei016_rules(analyzer):
    for issue in analyze_cei016(analyzer.model):
        analyzer.add_issue(
            issue.severity,
            issue.rule_id,
            _ied_from_location(issue.location),
            issue.location,
            issue.message,
        )


def _ied_from_location(location):
    if not location:
        return ""
    for part in location.split("/"):
        if part.startswith("IED="):
            return part[4:]
    return ""
