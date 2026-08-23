from .result import Issue
from .pcap import analyze_pcap


class Analyzer:
    def __init__(self, model, iec61850_enabled=True, cei016_enabled=True):
        self.model = model
        self.iec61850_enabled = iec61850_enabled
        self.cei016_enabled = cei016_enabled
        self.issues = []

    def add_issue(self, severity, rule_id, ied, location, description):
        self.issues.append(Issue(severity, rule_id, ied, location, description))

    def run(self):
        self.issues = []

        # Source validation is always performed.  A PCAP is evidence, so a
        # broken/incomplete capture must be reported rather than hidden.
        if getattr(self.model, 'source_type', '') == 'pcap':
            self.issues.extend(analyze_pcap(self.model))

        if self.iec61850_enabled:
            from rules.iec61850 import (
                run_basic_rules, run_dataset_rules,
                run_report_rules, run_goose_rules,
            )
            run_basic_rules(self)
            run_dataset_rules(self)
            run_report_rules(self)
            run_goose_rules(self)

        if self.cei016_enabled and getattr(self.model, 'source_type', '') == 'scl':
            from rules.cei016 import run_cei016_rules
            run_cei016_rules(self)

        return self.issues
