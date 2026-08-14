# IEC 61850 SCL Analyzer

Cross-platform Python/Tkinter analyzer for IEC 61850 SCL/CID/SCD/ICD files.

## Architecture

- `model.py` — effective IEC 61850 SCL model, including LNodeType inheritance and DO/DA/SDO/DAType resolution.
- `scl_parser.py` — backward-compatible import shim to `model.py`.
- `analyzer.py` — common issue collector and rule orchestration.
- `rules/basic.py` — general SCL/IED/LDevice/LN checks.
- `rules/datasets.py` — DataSet and FCDA checks.
- `rules/reports.py` — ReportControl/DataSet checks.
- `rules/goose.py` — GSEControl/DataSet checks.
- `rules/cei016.py` — adapter from the CEI 0-16 profile to the common Analyzer format.
- `cei016_observability.py` — CEI 0-16 V5 Annex T observability matrix.
- `cei016_profile.py` — matrix-driven CEI 0-16 validation using the effective model.
- `gui.py` — Tkinter GUI.
- `main.py` — GUI entry point; accepts an optional SCL path.
- `test_parser.py` — command-line regression test.

## Run

```bash
python main.py
```

or analyze a file immediately:

```bash
python main.py path/to/file.cid
```

Command-line test:

```bash
python test_parser.py path/to/file.cid
```

Disable CEI 0-16 for comparison:

```bash
python test_parser.py path/to/file.cid --no-cei016
```

CEI 0-16 checks are enabled by default under **Options -> CEI 0-16 checks**.

## Effective model

The CEI 0-16 validator does not treat the presence of `DOI`/`DAI` as the definition of the Logical Node model. It resolves the effective model through:

```text
LN
 └── LNodeType
      └── DO
           └── DOType
                ├── DA
                └── SDO
                     └── DOType
```

Structured data attributes are resolved through `DAType`/`BDA` as applicable.

This prevents false positives when a required DO or DA is defined by the type but is not explicitly repeated as an instance element.
