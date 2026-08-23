"""CEI 0-16 V5 observability matrix used by the profile validator.

The matrix describes effective model paths.  A path is considered present
when it is defined by the effective LNodeType/DOType/DAType model, even if
its DOI/DAI is not repeated in the LN instance.  This is deliberate: SCL
instances configure the model; they are not a complete duplicate of the type
definition.
"""

MANDATORY = "M"
CONDITIONAL = "C"
OPTIONAL = "O"

# Each entry applies to every instantiated LN of the specified class unless
# a prefix/instance constraint is supplied.
OBSERVABILITY_RULES = [
    {"id": "OBS-LLN0-001", "ln_class": "LLN0", "path": None, "requirement": MANDATORY, "description": "LLN0 shall be present in LD_Plant."},
    {"id": "OBS-LPHD-001", "ln_class": "LPHD", "path": "PhyNam.vendor", "requirement": MANDATORY, "description": "CCI manufacturer."},
    {"id": "OBS-LPHD-002", "ln_class": "LPHD", "path": "PhyNam.swRev", "requirement": MANDATORY, "description": "CCI software revision."},
    {"id": "OBS-LPHD-003", "ln_class": "LPHD", "path": "PhyNam.location", "requirement": MANDATORY, "description": "POD/location identifier."},

    {"id": "OBS-DPCC-001", "ln_class": "DPCC", "prefix": "PdC_Wi", "path": "WRtg.setMag", "requirement": MANDATORY, "description": "Active power rating."},
    {"id": "OBS-DPCC-002", "ln_class": "DPCC", "prefix": "PdC_Qi", "path": "VArRtg.setMag", "requirement": MANDATORY, "description": "Reactive power rating."},
    {"id": "OBS-DPCC-003", "ln_class": "DPCC", "prefix": "PdC_VA", "path": "VARtg.setMag", "requirement": MANDATORY, "description": "Apparent power rating."},
    {"id": "OBS-DPCC-004", "ln_class": "DPCC", "prefix": "PdC_Wa", "path": "WRtg.setMag", "requirement": MANDATORY, "description": "Active power absorption rating."},
    {"id": "OBS-DPCC-005", "ln_class": "DPCC", "prefix": "PdC_Qc", "path": "VArRtg.setMag", "requirement": MANDATORY, "description": "Reactive power capacitive rating."},

    {"id": "OBS-DECP-001", "ln_class": "DECP", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Plant connection point behaviour."},
    {"id": "OBS-DGEN-001", "ln_class": "DGEN", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Generation block behaviour."},
    {"id": "OBS-DGEN-002", "ln_class": "DGEN", "prefix": "SSGG", "path": "Health.stVal", "requirement": MANDATORY, "description": "Generation block health."},
    {"id": "OBS-DGEN-003", "ln_class": "DGEN", "prefix": "SSGG", "path": "GnGrId.stVal", "requirement": MANDATORY, "description": "Generation group identifier."},
    {"id": "OBS-DSTO-001", "ln_class": "DSTO", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Storage block behaviour."},
    {"id": "OBS-XCBR-001", "ln_class": "XCBR", "path": "Pos.stVal", "requirement": MANDATORY, "description": "General circuit breaker position."},

    {"id": "OBS-MMXU-001", "ln_class": "MMXU", "path": "TotW.mag", "requirement": MANDATORY, "description": "Active power measurement."},
    {"id": "OBS-MMXU-002", "ln_class": "MMXU", "prefix": "PdC", "path": "TotVAr.mag", "requirement": MANDATORY, "description": "Reactive power measurement."},
    {"id": "OBS-MMXU-003", "ln_class": "MMXU", "prefix": "PdC", "path": "PPV.phsAB.cVal.mag", "requirement": MANDATORY, "description": "Line-to-line voltage measurement."},
    {"id": "OBS-MMXU-004", "ln_class": "MMXU", "path": "A", "requirement": OPTIONAL, "description": "Phase current measurement."},

    {"id": "OBS-DWMX-001", "ln_class": "DWMX", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Active power limitation behaviour."},
    {"id": "OBS-DWMX-002", "ln_class": "DWMX", "path": "Health.stVal", "requirement": MANDATORY, "description": "Active power limitation health."},
    {"id": "OBS-DWMX-003", "ln_class": "DWMX", "path": "WMaxSptPct.mxVal.f", "requirement": MANDATORY, "description": "Active power limitation setpoint."},
    {"id": "OBS-DWMX-004", "ln_class": "DWMX", "path": "Mod.stVal", "requirement": MANDATORY, "description": "Active power limitation mode."},
    {"id": "OBS-DWMX-005", "ln_class": "DWMX", "path": "FctOpStAuto.stVal", "requirement": MANDATORY, "description": "Autonomous function status."},
    {"id": "OBS-DWMX-006", "ln_class": "DWMX", "path": "FctOpStEx.stVal", "requirement": MANDATORY, "description": "External function status."},

    {"id": "OBS-DAGC-001", "ln_class": "DAGC", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Active power setpoint behaviour."},
    {"id": "OBS-DAGC-002", "ln_class": "DAGC", "path": "Health.stVal", "requirement": MANDATORY, "description": "Active power setpoint health."},
    {"id": "OBS-DAGC-003", "ln_class": "DAGC", "path": "WSptPct.mxVal.f", "requirement": MANDATORY, "description": "Active power setpoint."},
    {"id": "OBS-DAGC-004", "ln_class": "DAGC", "path": "Mod.stVal", "requirement": MANDATORY, "description": "Active power modulation mode."},
    {"id": "OBS-DAGC-005", "ln_class": "DAGC", "path": "FctOpSt.stVal", "requirement": MANDATORY, "description": "Active power function status."},

    {"id": "OBS-DVAR-001", "ln_class": "DVAR", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Reactive power behaviour."},
    {"id": "OBS-DVAR-002", "ln_class": "DVAR", "path": "Health.stVal", "requirement": MANDATORY, "description": "Reactive power function health."},
    {"id": "OBS-DVAR-003", "ln_class": "DVAR", "path": "VArTgtSptPct.mxVal.f", "requirement": MANDATORY, "description": "Reactive power setpoint."},
    {"id": "OBS-DVAR-004", "ln_class": "DVAR", "path": "Mod.stVal", "requirement": MANDATORY, "description": "Reactive power mode."},
    {"id": "OBS-DVAR-005", "ln_class": "DVAR", "path": "FctOpSt.stVal", "requirement": MANDATORY, "description": "Reactive power function status."},

    {"id": "OBS-DFPF-001", "ln_class": "DFPF", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Power factor function behaviour."},
    {"id": "OBS-DFPF-002", "ln_class": "DFPF", "path": "Health.stVal", "requirement": MANDATORY, "description": "Power factor function health."},
    {"id": "OBS-DFPF-003", "ln_class": "DFPF", "path": "PFGnTgtSpt", "requirement": MANDATORY, "description": "Generation power factor setpoint."},
    {"id": "OBS-DFPF-004", "ln_class": "DFPF", "path": "PFLodTgtSpt", "requirement": MANDATORY, "description": "Load power factor setpoint."},
    {"id": "OBS-DFPF-005", "ln_class": "DFPF", "path": "Mod.stVal", "requirement": MANDATORY, "description": "Power factor mode."},
    {"id": "OBS-DFPF-006", "ln_class": "DFPF", "path": "FctOpSt.stVal", "requirement": MANDATORY, "description": "Power factor function status."},

    {"id": "OBS-DVVR-001", "ln_class": "DVVR", "path": "Beh.stVal", "requirement": MANDATORY, "description": "Voltage regulation behaviour."},
    {"id": "OBS-DVVR-002", "ln_class": "DVVR", "path": "Health.stVal", "requirement": MANDATORY, "description": "Voltage regulation health."},
    {"id": "OBS-DVVR-003", "ln_class": "DVVR", "path": "Mod.stVal", "requirement": MANDATORY, "description": "Voltage regulation mode."},
    {"id": "OBS-DVVR-004", "ln_class": "DVVR", "path": "FctOpSt.stVal", "requirement": MANDATORY, "description": "Voltage regulation status."},
    {"id": "OBS-DVVR-005", "ln_class": "DVVR", "path": "K.setMag", "requirement": MANDATORY, "description": "Q(V) slope parameter."},

    {"id": "OBS-DPMC-001", "ln_class": "DPMC", "path": "WSpt1", "requirement": MANDATORY, "description": "Q(V) lock-in/lock-out active-power threshold."},

    {"id": "OBS-DPFW-001", "ln_class": "DPFW", "path": "Beh.stVal", "requirement": MANDATORY, "description": "cos(phi)=f(P) behaviour."},
    {"id": "OBS-DPFW-002", "ln_class": "DPFW", "path": "Health.stVal", "requirement": MANDATORY, "description": "cos(phi)=f(P) health."},
    {"id": "OBS-DPFW-003", "ln_class": "DPFW", "path": "Mod.stVal", "requirement": MANDATORY, "description": "cos(phi)=f(P) mode."},
    {"id": "OBS-DPFW-004", "ln_class": "DPFW", "path": "FctOpSt.stVal", "requirement": MANDATORY, "description": "cos(phi)=f(P) status."},
    {"id": "OBS-DPFW-005", "ln_class": "DPFW", "path": "WSetA", "requirement": MANDATORY, "description": "Curve point A active-power setting."},
    {"id": "OBS-DPFW-006", "ln_class": "DPFW", "path": "PFSetA", "requirement": MANDATORY, "description": "Curve point A power-factor setting."},
    {"id": "OBS-DPFW-007", "ln_class": "DPFW", "path": "WSetB", "requirement": MANDATORY, "description": "Curve point B active-power setting."},
    {"id": "OBS-DPFW-008", "ln_class": "DPFW", "path": "PFSetB", "requirement": MANDATORY, "description": "Curve point B power-factor setting."},
    {"id": "OBS-DPFW-009", "ln_class": "DPFW", "path": "WSetC", "requirement": MANDATORY, "description": "Curve point C active-power setting."},
    {"id": "OBS-DPFW-010", "ln_class": "DPFW", "path": "PFSetC", "requirement": MANDATORY, "description": "Curve point C power-factor setting."},
    {"id": "OBS-DPFW-011", "ln_class": "DPFW", "path": "VLkIn", "requirement": MANDATORY, "description": "Curve lock-in threshold."},
    {"id": "OBS-DPFW-012", "ln_class": "DPFW", "path": "VLkOut", "requirement": MANDATORY, "description": "Curve lock-out threshold."},
]


def rules_for_ln(ln_class):
    return [r for r in OBSERVABILITY_RULES if r["ln_class"] == ln_class]


__all__ = ["MANDATORY", "CONDITIONAL", "OPTIONAL", "OBSERVABILITY_RULES", "rules_for_ln"]
