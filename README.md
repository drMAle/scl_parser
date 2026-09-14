# IEC 61850 SCL / PCAP Analyzer

Unified IEC 61850 model architecture for validating SCL files, validating MMS discovery captures, and comparing an expected SCL model with an observed PCAP model.

## Core principle: observation never invents

The PCAP parser is an **observation parser**. It creates model elements only from information actually decoded from the capture. It never copies or infers missing objects from an SCL file.

If a required discovery stage is absent, the supplied test evidence is considered incomplete and the analyzer reports an **ERROR**.

Therefore:

- SCL = expected/declarative model.
- PCAP = observed/evidence model.
- Missing expected object in PCAP = `ERROR` during comparison.
- Missing required discovery evidence = `ERROR`.
- Observed object not declared by SCL = `INFO` by default.
- No observed object is synthesized merely to make a comparison pass.

## Architecture

```text
Model
├── SCLModel       <- built from SCL/XML
└── PcapModel      <- built from PCAP/MMS discovery

sources/
├── scl/           <- XML/SCL source parsing
└── pcap/          <- packet capture parsing + observation builder

rules/
├── iec61850/      <- model validation rules
└── cei016/        <- CEI 0-16 profile rules

comparison/        <- expected SCL vs observed PCAP
analyzer/           <- orchestration and results
gui/                <- Tkinter UI
```

## PCAP discovery currently decoded

The MMS decoder implements the BER/MMS structures needed for:

- `GetNameList`
- `Identify`
- `GetVariableAccessAttributes`
- `GetNamedVariableListAttributes`
- `Read` / `ReadResponse` with explicitly observed MMS values

The PCAP model uses these transactions to construct an observed XML-shaped model containing only observed:

- Logical Devices
- Logical Nodes
- Data Objects
- Data Attributes / nested SDI paths
- DataSets and observed members

The mapping follows the IEC 61850-8-1 MMS service model; `GetNameList` is interpreted using its encoded MMS object class and scope, while `GetVariableAccessAttributes` and `GetNamedVariableListAttributes` provide lower-level type/dataset evidence. IEC 61850-8-1 defines these mappings to MMS. 

## Required discovery evidence

For a capture to be accepted as a complete model-discovery test, the analyzer requires evidence for:

- `GetServerDirectory`
- `GetLogicalNodeDirectory`
- `GetDataDirectory`
- `GetVariableAccessAttributes`
- `GetDataSetDirectory`

The parser does not mark a stage as observed unless the corresponding MMS evidence was decoded/correlated.

## GUI

`Options` contains:

- `IEC 61850 checks`
- `CEI 0-16 checks`

The same analyzer entry point is used for SCL and PCAP models. The File menu also provides a separate **Check default values in PCAP** action; it loads a capture and evaluates only observed Read/ReadResponse values, without requiring SCL or changing discovery validation. CEI 0-16 rules are currently applied to SCL models, because the current CEI profile is a configuration/profile validator rather than an observation rule set.

## Command line

Open the GUI normally:

```text
python main.py
```

Open a file directly:

```text
python main.py plant.cid
python main.py discovery.pcapng
```

or explicitly select PCAP:

```text
python main.py discovery.pcapng --pcap
```

## Standard library

The core project has no mandatory third-party Python dependency. Tkinter must be available in the Python installation used to run the GUI.
