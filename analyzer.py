from dataclasses import dataclass


@dataclass
class Issue:

    severity: str
    rule_id: str
    ied: str
    location: str
    description: str

    def as_tuple(self):

        return (
            self.severity,
            self.rule_id,
            self.ied,
            self.location,
            self.description
        )


class Analyzer:

    def __init__(
        self,
        model,
        cei016_enabled=True,
        cei57142_enabled=True
    ):

        self.model = model
        self.cei016_enabled = cei016_enabled
        self.cei57142_enabled = cei57142_enabled
        self.issues = []

    def add_issue(
        self,
        severity,
        rule_id,
        ied,
        location,
        description
    ):

        self.issues.append(
            Issue(
                severity=severity,
                rule_id=rule_id,
                ied=ied,
                location=location,
                description=description
            )
        )

    def run(self):

        self.issues = []

        from rules.basic import run_basic_rules
        from rules.datasets import run_dataset_rules
        from iec61850_rules.reports import run_report_rules
        from iec61850_rules.goose import run_goose_rules

        run_basic_rules(self)
        run_dataset_rules(self)
        run_report_rules(self)
        run_goose_rules(self)

        # -----------------------------------------------------
        # CEI 0-16 checks
        # -----------------------------------------------------

        if self.cei016_enabled:

            from rules.cei016 import run_cei016_rules

            run_cei016_rules(self)

        # -----------------------------------------------------
        # CEI 57-142 checks
        # -----------------------------------------------------

        if self.cei57142_enabled:
            from tkinter import Tk, messagebox
            messagebox.showwarning(
                "Warning",
                "CEIXX is an experimental feature"
            )
            from rules.cei57142 import run_cei57142_rules
            run_cei57142_rules(self)

        return self.issues
