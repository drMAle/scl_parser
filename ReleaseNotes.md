# Release Notes

## Validation Checks

### General IEC 61850 / SCL Checks

* **SCL Structure**

  * Verifies that the SCL file contains at least one IED.
  * Checks the basic `IED → AccessPoint → Server → LDevice` hierarchy.

* **IED**

  * Checks for missing IED names.
  * Detects duplicated IED names.
  * Checks that each IED contains at least one `AccessPoint`.

* **AccessPoint / Server**

  * Checks that each `AccessPoint` contains a `Server`.

* **Logical Device**

  * Checks for missing `LDevice.inst`.
  * Checks that each `LDevice` contains an `LN0`.

* **Logical Nodes**

  * Checks for missing `lnClass`.
  * Checks for missing `inst`.
  * Detects duplicated Logical Nodes within the same LDevice.

* **DataSets**

  * Checks for missing DataSet names.
  * Detects duplicated DataSet names within the same Logical Node.
  * Checks FCDA references for missing `ldInst`, `lnClass`, `lnInst` and `doName`.

* **Reports**

  * Checks for missing `ReportControl` names.
  * Checks that `ReportControl` references an existing DataSet.
  * Reports missing `datSet` references.

* **GOOSE**

  * Checks for missing `GSEControl` names.
  * Checks that `GSEControl` references an existing DataSet.
  * Reports missing `datSet` references.

### CEI 0-16 Checks

CEI 0-16 validation can be enabled or disabled from **Options → CEI 0-16 checks** and is enabled by default.

* **Logical Device**

  * Checks for the presence of the mandatory `LD_Plant` Logical Device.
  * Detects multiple `LD_Plant` instances.

* **Mandatory Logical Nodes**

  * Checks the presence of the required Logical Nodes within `LD_Plant`:

    * `LLN0`
    * `LPHD`
    * `DPCC`
    * `DECP`
    * `DGEN`
    * `DSTO`
    * `XCBR`
    * `MMXU`
    * `DWMX`
    * `DAGC`
    * `DVAR`
    * `DFPF`
    * `DVVR`
    * `DPMC`
    * `DPFW`

* **Mandatory Data Objects**

  * Checks the presence of the required Data Objects for each CEI 0-16 Logical Node, including:

    * `PhyNam`
    * `WRtg`
    * `VArRtg`
    * `VARtg`
    * `Beh`
    * `Health`
    * `GnGrId`
    * `Pos`
    * `TotW`
    * `TotVAr`
    * `PPV`
    * `WMaxSptPct`
    * `WSptPct`
    * `VArTgtSptPct`
    * `PFGnTgtSpt`
    * `PFLodTgtSpt`
    * `K`
    * `WSpt1`
    * `WSetA`
    * `PFSetA`
    * `WSetB`
    * `PFSetB`
    * `WSetC`
    * `PFSetC`
    * `VLkIn`
    * `VLkOut`

* **Mandatory Data Attributes**

  * Checks the presence of the specified Data Attributes, including:

    * `vendor`
    * `swRev`
    * `location`
    * `setMag`
    * `stVal`
    * `mag`
    * `ctlVal`

### Analysis Results

* Displays all validation findings in a structured results table.
* Reports **severity**, **rule ID**, **IED**, **location**, and **description**.
* Displays a summary dialog at the end of the analysis.
* Distinguishes between **errors** and **warnings**.
* CEI 0-16 checks are enabled by default and can be disabled from the **Options** menu.

> **Note:** The current CEI 0-16 implementation performs presence checks for Logical Nodes, Data Objects and selected Data Attributes. It does not yet constitute a complete CEI 0-16 compliance verification.
