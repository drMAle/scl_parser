# CEI 57-142:2026 validator layer

Baseline: CEI 57-142:2026-07, in force 2026-08-01.

Implemented:
- single `LD_Plant`;
- PF1 mandatory observability;
- section prefixes;
- LPHD identification;
- PCC ratings;
- plant/generation/storage availability;
- PCC measurements;
- generation-source/storage/single-generator measurements;
- DG breaker position;
- per-generator state and identifier;
- SCL-provable semantic ranges;
- communication evidence (DataSet/ReportControl).

The matrix uses the CEI 57-142 M/O/C/R/E/F model.

Important: SCL alone cannot prove runtime latency, actual 4 s transmission,
cybersecurity, certificates, NTP/NTS, RBAC enforcement, firewall/VPN,
secure boot or firmware-update behaviour. Those require separate evidence.
