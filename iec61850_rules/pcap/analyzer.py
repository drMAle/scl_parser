"""
IEC 61850 PCAP analysis rules.

The analyzer works on an already loaded PcapModel.

It does NOT parse the capture itself. Parsing remains the responsibility
of pcap_model.py / PcapModel.

The resulting issues are compatible with the common GUI result format:

    severity
    rule_id
    ied
    location
    description
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PcapIssue:
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
            self.description,
        )


class PcapAnalyzer:

    def __init__(self, model):
        self.model = model
        self.issues: list[PcapIssue] = []

    # ============================================================
    # PUBLIC API
    # ============================================================

    def run(self) -> list[PcapIssue]:
        self.issues = []

        self._check_capture()
        self._check_mms()
        self._check_discovery()
        self._check_get_name_list()
        self._check_get_variable_access_attributes()

        return self.issues

    # ============================================================
    # ISSUE HANDLING
    # ============================================================

    def add_issue(
        self,
        severity: str,
        rule_id: str,
        location: str,
        description: str,
        ied: str = "-",
    ):
        self.issues.append(
            PcapIssue(
                severity=severity,
                rule_id=rule_id,
                ied=ied,
                location=location,
                description=description,
            )
        )

    # ============================================================
    # CAPTURE
    # ============================================================

    def _check_capture(self):

        if self.model.packet_count == 0:

            self.add_issue(
                "ERROR",
                "PCAP-001",
                "PCAP",
                "No packets were decoded from the capture.",
            )

            return

        if self.model.parse_warnings:

            for warning in self.model.parse_warnings:

                self.add_issue(
                    "WARNING",
                    "PCAP-002",
                    "PCAP parser",
                    warning,
                )

    # ============================================================
    # MMS
    # ============================================================

    def _check_mms(self):

        if self.model.mms_count == 0:

            self.add_issue(
                "INFO",
                "PCAP-MMS-001",
                "MMS",
                "No MMS traffic on TCP port 102 was detected.",
            )

            return

        self.add_issue(
            "INFO",
            "PCAP-MMS-002",
            "MMS",
            f"Detected {self.model.mms_count} MMS/TCP-102 packet(s).",
        )

        if self.model.mms_warnings:

            for warning in self.model.mms_warnings:

                self.add_issue(
                    "WARNING",
                    "PCAP-MMS-003",
                    "MMS decoder",
                    warning,
                )

    # ============================================================
    # IEC 61850 DISCOVERY
    # ============================================================

    def _check_discovery(self):

        if self.model.discovery_count == 0:

            self.add_issue(
                "WARNING",
                "PCAP-DISC-001",
                "MMS discovery",
                "No IEC 61850 discovery transaction was detected.",
            )

            return

        self.add_issue(
            "INFO",
            "PCAP-DISC-002",
            "MMS discovery",
            (
                f"Detected {self.model.discovery_count} packet(s) "
                "containing IEC 61850 discovery activity."
            ),
        )

    # ============================================================
    # GET NAME LIST
    # ============================================================

    def _check_get_name_list(self):

        transactions = self.model.get_name_list

        if not transactions:

            self.add_issue(
                "INFO",
                "PCAP-DISC-003",
                "GetNameList",
                "No correlated GetNameList request/response was found.",
            )

            return

        for index, transaction in enumerate(transactions, 1):

            location = f"GetNameList #{index}"

            if transaction.invoke_id is None:

                self.add_issue(
                    "WARNING",
                    "PCAP-MMS-010",
                    location,
                    "GetNameList transaction has no invoke ID.",
                )

            if not transaction.identifiers:

                self.add_issue(
                    "WARNING",
                    "PCAP-MMS-011",
                    location,
                    "GetNameList response contains no identifiers.",
                )

            if transaction.more_follows:

                self.add_issue(
                    "INFO",
                    "PCAP-MMS-012",
                    location,
                    (
                        "GetNameList response indicates that additional "
                        "identifiers follow."
                    ),
                )

    # ============================================================
    # GET VARIABLE ACCESS ATTRIBUTES
    # ============================================================

    def _check_get_variable_access_attributes(self):

        transactions = self.model.get_variable_access_attributes

        if not transactions:

            self.add_issue(
                "INFO",
                "PCAP-DISC-010",
                "GetVariableAccessAttributes",
                (
                    "No correlated GetVariableAccessAttributes "
                    "transaction was found."
                ),
            )

            return

        for index, transaction in enumerate(transactions, 1):

            location = f"GetVariableAccessAttributes #{index}"

            object_name = transaction.object_name

            if not object_name:

                self.add_issue(
                    "WARNING",
                    "PCAP-MMS-020",
                    location,
                    "Transaction has no object name.",
                )

                continue

            runtime_object = transaction.data_object

            if runtime_object is None:

                self.add_issue(
                    "WARNING",
                    "PCAP-MMS-021",
                    location,
                    (
                        f"No runtime data object was reconstructed for "
                        f"'{object_name}'."
                    ),
                )

                continue

            if not runtime_object.data_attributes:

                self.add_issue(
                    "WARNING",
                    "PCAP-MMS-022",
                    location,
                    (
                        f"No data attributes were decoded for "
                        f"'{object_name}'."
                    ),
                )

            for attribute in runtime_object.data_attributes:

                if not attribute.name:

                    self.add_issue(
                        "WARNING",
                        "PCAP-MMS-023",
                        location,
                        (
                            f"An empty data attribute was found in "
                            f"'{object_name}'."
                        ),
                    )

                if not attribute.path:

                    self.add_issue(
                        "WARNING",
                        "PCAP-MMS-024",
                        location,
                        (
                            f"Data attribute '{attribute.name}' in "
                            f"'{object_name}' has no decoded path."
                        ),
                    )

                if attribute.type == "unknown":

                    self.add_issue(
                        "WARNING",
                        "PCAP-MMS-025",
                        location,
                        (
                            f"Data attribute '{attribute.path}' in "
                            f"'{object_name}' has unknown ASN.1 type."
                        ),
                    )

    # ============================================================
    # SUMMARY
    # ============================================================

    @property
    def errors(self):

        return [
            issue
            for issue in self.issues
            if issue.severity == "ERROR"
        ]

    @property
    def warnings(self):

        return [
            issue
            for issue in self.issues
            if issue.severity == "WARNING"
        ]

    @property
    def infos(self):

        return [
            issue
            for issue in self.issues
            if issue.severity == "INFO"
        ]


def analyze_pcap(model) -> list[PcapIssue]:
    """
    Convenience function.

    Example:

        model = PcapModel(Path(filename))
        model.load()

        issues = analyze_pcap(model)
    """

    analyzer = PcapAnalyzer(model)

    return analyzer.run()