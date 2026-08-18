# IEC 61850 Report / GOOSE package

This package separates static SCL validation from PCAP observation.

## SCL

- `reports.py`: `ReportControl -> DataSet -> FCDA` checks and basic report configuration checks.
- `goose.py`: `GSEControl -> DataSet -> FCDA` checks plus `Communication/GSE/Address` checks.

Both expose the existing parser API:

```python
run_report_rules(analyzer)
run_goose_rules(analyzer)
```

They are compatible with the current `Analyzer.add_issue()` interface.

## PCAP

- `pcap/reader.py`: dependency-free classic PCAP Ethernet reader.
- `pcap/goose.py`: IEC 61850 GOOSE frame parser for EtherType `0x88B8`, including VLAN, APPID and common GOOSE fields.
- `pcap/reports.py`: MMS/TCP-102 observation. If `tshark` is installed it asks Wireshark for MMS JSON; otherwise it safely falls back to TCP/102 detection.
- `pcap/analyzer.py`: combines GOOSE and MMS observations.

### Important limitation

A PCAP alone does not identify a semantic IEC 61850 Report as reliably as a decoded MMS session with the negotiated presentation context. Therefore the fallback mode reports MMS/TCP-102 observations, not a false semantic `ReportControl` match. Full SCL <-> PCAP cross-validation should be implemented on top of these observations using the SCL model and, preferably, tshark's decoded MMS fields.

## Integration

Copy `reports.py` and `goose.py` into the existing `rules/` directory. Copy the `pcap/` directory next to `rules/`.

The existing analyzer can keep:

```python
from rules.reports import run_report_rules
from rules.goose import run_goose_rules
```

No change to `model.py` is required by this package.
