# SCL Analyzer — Complete Integrated Package

This package combines the current IEC 61850 SCL validator with the CEI 0-16 validation layer, the CEI 57-142 validator layer, and the initial PCAP/discovery analysis and SCL↔PCAP comparison functions.

## Main functions

### File → Open SCL
Runs the existing SCL validation stack:

- IEC 61850/SCL structural checks
- Dataset checks
- Report checks
- GOOSE checks
- CEI 0-16 checks (optional, enabled by default)
- CEI 57-142 checks (optional, enabled by default)

### File → Open PCAP
Loads a `.pcap` or `.pcapng` capture and performs the current capture-level checks:

- Ethernet/IPv4/TCP parsing
- MMS/TCP 102 detection
- preliminary discovery detection
- capture completeness warnings where the available evidence is insufficient

The PCAP module deliberately does not claim full MMS/ASN.1 discovery conformance yet; missing evidence is reported as WARNING rather than converted into false-positive errors.

### File → Compare SCL and PCAP
Loads one SCL and one capture and performs the current SCL/runtime alignment checks. The comparison layer is designed to be extended with complete MMS discovery reconstruction and later report/GOOSE timing analysis.

## Architecture

- `model.py` — effective IEC 61850 SCL model and inheritance resolution
- `scl_parser.py` — backward-compatible import layer
- `rules/` — generic IEC 61850, Dataset, Report, GOOSE and CEI 0-16 adapters
- `cei57142/` — CEI 57-142 validator package
- `cei57142_profile.py` — top-level CEI 57-142 entry point
- `pcap_model.py` — capture model
- `pcap_analyzer.py` — PCAP validation
- `scl_pcap_compare.py` — SCL/PCAP comparison
- `gui.py` — Tkinter GUI
- `main.py` — application entry point

## Run

```bash
python main.py
```

No third-party Python package is required by the current PCAP layer.

## Important

The PCAP functionality is intentionally incremental. The next development step is a proper MMS/ASN.1 discovery decoder so that the runtime model can be populated with Server, Logical Device, Logical Node, Data Object/Data Attribute, Dataset and Report Control Block information. Timing analysis (report periodicity, jitter, second-zero alignment, sequence handling and GOOSE timing) can then be added without changing the GUI architecture.
