
"""
CEI 0-16 V5 project profile checker for the IEC 61850 SCL parser.

This module is independent from the GUI and uses the resolved LNodeType model
provided by the current SCL parser, including inherited definitions.

The rules are based on the CEI 0-16 profile supplied for this project.
They are intentionally divided into:
    * mandatory structural checks -> ERROR
    * semantic/configuration checks -> WARNING
    * optional functions/elements not instantiated -> INFO

Usage:
    from cei016_profile import analyze_cei016
    issues = analyze_cei016(model)
"""

from dataclasses import dataclass


# ============================================================================
# Result
# ============================================================================

@dataclass
class CEI016Issue:
    severity: str
    message: str
    location: str = ""

    def __str__(self):
        if self.location:
            return f"[{self.severity}] {self.location}: {self.message}"
        return f"[{self.severity}] {self.message}"


# ============================================================================
# CEI 0-16 project profile
# ============================================================================

REQUIRED_LOGICAL_DEVICE = "LD_Plant"

# Core model required by the project profile.
REQUIRED_LN_CLASSES = (
    "LLN0",
    "LPHD",
    "DPCC",
    "DECP",
    "DGEN",
    "DSTO",
    "XCBR",
    "MMXU",
)

# Control/regulation functions. These are function-dependent: if instantiated,
# their internal structure is checked. If absent, the checker reports INFO.
OPTIONAL_LN_CLASSES = {
    "DWMX": "Active power limitation",
    "DAGC": "Active power modulation / setpoint",
    "DVAR": "Reactive power modulation / setpoint",
    "DFPF": "Power factor setpoint",
    "DVVR": "Voltage regulation Q(V)",
    "DPMC": "Q(V) lock-in / lock-out",
    "DPFW": "cos(phi) = f(P) regulation",
}

REQUIRED_DOS = {
    "LPHD": ("PhyNam",),
    "DPCC": ("WRtg", "VArRtg", "VARtg"),
    "DECP": ("Beh",),
    "DGEN": ("Beh", "Health", "GnGrId"),
    "DSTO": ("Beh",),
    "XCBR": ("Pos",),
    "MMXU": ("TotW", "TotVAr", "PPV"),

    "DWMX": (
        "Beh", "Health", "WMaxSptPct", "Mod",
        "FctOpStAuto", "FctOpStEx",
    ),
    "DAGC": ("Beh", "Health", "WSptPct", "Mod", "FctOpSt"),
    "DVAR": ("Beh", "Health", "VArTgtSptPct", "Mod", "FctOpSt"),
    "DFPF": (
        "Beh", "Health", "PFGnTgtSpt", "PFLodTgtSpt",
        "Mod", "FctOpSt",
    ),
    "DVVR": ("Beh", "Health", "Mod", "FctOpSt", "K"),
    "DPMC": ("WSpt1",),
    "DPFW": (
        "Beh", "Health", "Mod", "FctOpSt",
        "WSetA", "PFSetA", "WSetB", "PFSetB",
        "WSetC", "PFSetC", "VLkIn", "VLkOut",
    ),
}

# Required instantiated DOI/SDI/DAI paths.
REQUIRED_PATHS = {
    "LPHD": (
        "PhyNam.vendor",
        "PhyNam.swRev",
        "PhyNam.location",
    ),
    "DPCC": (
        "WRtg.setMag",
        "VArRtg.setMag",
        "VARtg.setMag",
    ),
    "DECP": ("Beh.stVal",),
    "DGEN": ("Beh.stVal", "Health.stVal", "GnGrId.stVal"),
    "DSTO": ("Beh.stVal",),
    "XCBR": ("Pos.stVal",),
    "MMXU": ("TotW.mag", "TotVAr.mag", "PPV.mag"),

    "DWMX": (
        "Beh.stVal", "Health.stVal", "WMaxSptPct.mxVal.f",
        "Mod.stVal", "FctOpStAuto.stVal", "FctOpStEx.stVal",
    ),
    "DAGC": (
        "Beh.stVal", "Health.stVal", "WSptPct.mxVal.f",
        "Mod.stVal", "FctOpSt.stVal",
    ),
    "DVAR": (
        "Beh.stVal", "Health.stVal", "VArTgtSptPct.mxVal.f",
        "Mod.stVal", "FctOpSt.stVal",
    ),
    "DFPF": (
        "Beh.stVal", "Health.stVal", "Mod.stVal", "FctOpSt.stVal",
        "PFGnTgtSpt", "PFLodTgtSpt",
    ),
    "DVVR": (
        "Beh.stVal", "Health.stVal", "Mod.stVal",
        "FctOpSt.stVal", "K.setMag",
    ),
    "DPMC": ("WSpt1.ctlVal",),
    "DPFW": (
        "Beh.stVal", "Health.stVal", "Mod.stVal", "FctOpSt.stVal",
        "WSetA", "PFSetA", "WSetB", "PFSetB",
        "WSetC", "PFSetC", "VLkIn", "VLkOut",
    ),
}

OPTIONAL_DOS = {
    "MMXU": ("A",),
}

CONTROL_LN_CLASSES = tuple(OPTIONAL_LN_CLASSES)

CEI016_NAMESPACE = "IEC 61850-CEI016:2025"

# These are deliberately used for semantic warnings, not hard compliance
# failures, because actual state enumeration is also constrained by the
# resolved type definitions in the SCL.
COMMON_BEH_VALUES = {
    "on", "off", "blocked", "test", "test/blocked",
    "on-blocked", "off-blocked", "inactive",
}
COMMON_MOD_VALUES = COMMON_BEH_VALUES
COMMON_HEALTH_VALUES = {
    "ok", "warning", "alarm", "failure",
    "non-operational", "not available",
}


# ============================================================================
# Generic helpers
# ============================================================================

def _error(message, location=""):
    return CEI016Issue("ERROR", message, location)


def _warning(message, location=""):
    return CEI016Issue("WARNING", message, location)


def _info(message, location=""):
    return CEI016Issue("INFO", message, location)


def _iter_devices(model):
    for ied in getattr(model, "ieds", []):
        for access_point in getattr(ied, "access_points", []):
            for server in getattr(access_point, "servers", []):
                for l_device in getattr(server, "l_devices", []):
                    yield ied, access_point, server, l_device


def _iter_lns(l_device, ln_class=None):
    for ln in getattr(l_device, "all_logical_nodes", []):
        if ln_class is None or getattr(ln, "ln_class", None) == ln_class:
            yield ln


def _location(ied, access_point, server, l_device, ln=None):
    parts = []
    if getattr(ied, "name", None):
        parts.append(f"IED={ied.name}")
    if getattr(access_point, "name", None):
        parts.append(f"AP={access_point.name}")
    if getattr(server, "name", None):
        parts.append(f"Server={server.name}")

    ld_name = getattr(l_device, "name", None) or getattr(l_device, "inst", None)
    if ld_name:
        parts.append(f"LDevice={ld_name}")

    if ln is not None:
        parts.append(f"LN={getattr(ln, 'identifier', '')}")

    return "/".join(parts)


def _normalise(value):
    if value is None:
        return ""
    return str(value).strip()


def _get_do(ln, name):
    return ln.get_data_object(name)


def _get_dai(data_object, name):
    return data_object.get_data_attribute(name)


def _get_sdi(data_object, name):
    return data_object.get_sub_data_object(name)


def _resolve_path(ln, path):
    parts = path.split(".")
    if not parts:
        return None

    current = _get_do(ln, parts[0])
    if current is None:
        return None

    for index, part in enumerate(parts[1:]):
        if index == len(parts[1:]) - 1:
            return _get_dai(current, part)

        current = _get_sdi(current, part)
        if current is None:
            return None

    return current


def _value(ln, path):
    item = _resolve_path(ln, path)
    return None if item is None else getattr(item, "value", None)


def _check_do(ln, do_name, issues, location):
    if not ln.has_data_object(do_name):
        issues.append(
            _error(f"Required DO '{do_name}' is missing.", location)
        )


def _check_path(ln, path, issues, location):
    if _resolve_path(ln, path) is None:
        issues.append(
            _error(f"Required path '{path}' is missing.", location)
        )


# ============================================================================
# Structural checks
# ============================================================================

def check_ld_plant(model, issues):
    found = []

    for ied, ap, server, ld in _iter_devices(model):
        ld_name = getattr(ld, "name", None)
        ld_inst = getattr(ld, "inst", None)

        if ld_name == REQUIRED_LOGICAL_DEVICE or ld_inst == REQUIRED_LOGICAL_DEVICE:
            found.append((ied, ap, server, ld))

    if not found:
        issues.append(
            _error(
                "Required Logical Device 'LD_Plant' was not found."
            )
        )
        return

    if len(found) > 1:
        issues.append(
            _error(
                f"Multiple Logical Devices identified as '{REQUIRED_LOGICAL_DEVICE}' "
                f"were found ({len(found)})."
            )
        )


def check_single_logical_device(model, issues):
    for ied in getattr(model, "ieds", []):
        count = sum(
            len(getattr(server, "l_devices", []))
            for ap in getattr(ied, "access_points", [])
            for server in getattr(ap, "servers", [])
        )

        if count > 1:
            issues.append(
                _warning(
                    f"IED contains {count} Logical Devices. "
                    f"The CEI 0-16 project profile expects the plant model "
                    f"to be contained in '{REQUIRED_LOGICAL_DEVICE}'.",
                    f"IED={getattr(ied, 'name', '')}",
                )
            )


def check_required_logical_nodes(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        location = _location(ied, ap, server, ld)

        for ln_class in REQUIRED_LN_CLASSES:
            if ln_class == "LLN0":
                if getattr(ld, "ln0", None) is None:
                    issues.append(_error("Required LLN0 is missing.", location))
                continue

            if not list(_iter_lns(ld, ln_class)):
                issues.append(
                    _error(
                        f"Required Logical Node class '{ln_class}' is missing.",
                        location,
                    )
                )


def check_optional_logical_nodes(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        location = _location(ied, ap, server, ld)

        for ln_class, description in OPTIONAL_LN_CLASSES.items():
            if not list(_iter_lns(ld, ln_class)):
                issues.append(
                    _info(
                        f"Optional function '{ln_class}' ({description}) "
                        "is not instantiated.",
                        location,
                    )
                )


def check_instantiated_profile(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln_class, do_names in REQUIRED_DOS.items():
            for ln in _iter_lns(ld, ln_class):
                location = _location(ied, ap, server, ld, ln)

                for do_name in do_names:
                    _check_do(ln, do_name, issues, location)

                for path in REQUIRED_PATHS.get(ln_class, ()):
                    _check_path(ln, path, issues, location)


# ============================================================================
# Type system / inheritance
# ============================================================================

def check_lnode_types(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            location = _location(ied, ap, server, ld, ln)
            ln_type = getattr(ln, "ln_type", None)

            if not ln_type:
                issues.append(
                    _warning("Logical Node has no lnType.", location)
                )
                continue

            if model.get_lnode_type(ln_type) is None:
                issues.append(
                    _error(
                        f"LNodeType '{ln_type}' referenced by the Logical "
                        "Node does not exist.",
                        location,
                    )
                )
                continue

            try:
                model.resolve_lnode_type(ln_type)
            except ValueError as exc:
                issues.append(
                    _error(
                        f"Cannot resolve LNodeType '{ln_type}': {exc}",
                        location,
                    )
                )


def check_instantiated_dos_against_types(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            location = _location(ied, ap, server, ld, ln)
            ln_type = getattr(ln, "ln_type", None)

            if not ln_type:
                continue

            for do_name in ln.get_data_object_names():
                if not ln.has_defined_data_object(do_name):
                    issues.append(
                        _warning(
                            f"DOI '{do_name}' is instantiated but is not "
                            f"defined by resolved LNodeType '{ln_type}'.",
                            location,
                        )
                    )


# ============================================================================
# Semantic checks
# ============================================================================

def check_dgen_semantics(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        seen_inst = set()
        seen_ids = set()

        for ln in _iter_lns(ld, "DGEN"):
            location = _location(ied, ap, server, ld, ln)
            inst = _normalise(getattr(ln, "inst", None))

            if not inst:
                continue

            if inst in seen_inst:
                issues.append(
                    _warning(f"Duplicate DGEN inst='{inst}'.", location)
                )
            seen_inst.add(inst)

            group_id = _normalise(_value(ln, "GnGrId.stVal"))
            if not group_id:
                continue

            try:
                numeric_id = int(group_id)
            except ValueError:
                issues.append(
                    _warning(
                        f"GnGrId.stVal='{group_id}' is not a positive integer.",
                        location,
                    )
                )
                continue

            if numeric_id <= 0:
                issues.append(
                    _warning(
                        f"GnGrId.stVal='{group_id}' is not a positive integer.",
                        location,
                    )
                )

            if numeric_id in seen_ids:
                issues.append(
                    _warning(
                        f"Duplicate GnGrId.stVal='{numeric_id}'.",
                        location,
                    )
                )
            seen_ids.add(numeric_id)

            if inst.isdigit() and numeric_id != int(inst):
                issues.append(
                    _warning(
                        f"DGEN inst='{inst}' is inconsistent with "
                        f"GnGrId.stVal='{group_id}'.",
                        location,
                    )
                )


def check_state_values(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            location = _location(ied, ap, server, ld, ln)

            for do_name, allowed, label in (
                ("Beh", COMMON_BEH_VALUES, "Beh.stVal"),
                ("Mod", COMMON_MOD_VALUES, "Mod.stVal"),
                ("Health", COMMON_HEALTH_VALUES, "Health.stVal"),
            ):
                do = _get_do(ln, do_name)
                if do is None:
                    continue

                dai = _get_dai(do, "stVal")
                if dai is None:
                    continue

                value = _normalise(dai.value)
                if not value:
                    issues.append(
                        _warning(
                            f"{label} is present but has no configured value.",
                            location,
                        )
                    )
                elif value.lower() not in allowed:
                    issues.append(
                        _warning(
                            f"{label} has unrecognised value '{value}'.",
                            location,
                        )
                    )


def check_measurement_structure(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in _iter_lns(ld, "MMXU"):
            location = _location(ied, ap, server, ld, ln)

            for do_name in ("TotW", "TotVAr", "PPV"):
                do = _get_do(ln, do_name)
                if do is None:
                    continue

                mag = _get_sdi(do, "mag")
                if mag is None:
                    # Some SCLs instantiate mag directly as a DAI.
                    mag_dai = _get_dai(do, "mag")
                    if mag_dai is None:
                        issues.append(
                            _warning(
                                f"MMXU DO '{do_name}' does not contain "
                                "a valid 'mag' measurement structure.",
                                location,
                            )
                        )
                    continue

                f_dai = _get_dai(mag, "f")
                if f_dai is None:
                    issues.append(
                        _warning(
                            f"MMXU DO '{do_name}' has 'mag' but no 'f' value.",
                            location,
                        )
                    )

            # A is optional; validate it only when present.
            if ln.has_data_object("A"):
                do = _get_do(ln, "A")
                mag = _get_sdi(do, "mag")
                if mag is None and _get_dai(do, "mag") is None:
                    issues.append(
                        _warning(
                            "Optional MMXU.A is present but has no valid "
                            "'mag' measurement structure.",
                            location,
                        )
                    )


def check_control_semantics(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln_class in CONTROL_LN_CLASSES:
            for ln in _iter_lns(ld, ln_class):
                location = _location(ied, ap, server, ld, ln)

                for do in getattr(ln, "data_objects", []):
                    ctl_model = _get_dai(do, "ctlModel")
                    st_val = _get_dai(do, "stVal")

                    if ctl_model is not None:
                        if not _normalise(ctl_model.value):
                            issues.append(
                                _warning(
                                    f"Control DO '{do.name}' has an empty "
                                    "ctlModel.",
                                    location,
                                )
                            )

                        if st_val is None:
                            issues.append(
                                _warning(
                                    f"Control DO '{do.name}' has ctlModel "
                                    "but no stVal.",
                                    location,
                                )
                            )

                    for timeout_name in ("sboTimeout", "operTimeout"):
                        timeout = _get_dai(do, timeout_name)
                        if timeout is None:
                            continue

                        value = _normalise(timeout.value)
                        if not value:
                            issues.append(
                                _warning(
                                    f"Control DO '{do.name}' has an empty "
                                    f"{timeout_name}.",
                                    location,
                                )
                            )
                            continue

                        try:
                            numeric = int(value)
                            if numeric < 0:
                                raise ValueError
                        except ValueError:
                            issues.append(
                                _warning(
                                    f"Control DO '{do.name}' has invalid "
                                    f"{timeout_name}='{value}'.",
                                    location,
                                )
                            )


def check_dpfw_curve(model, issues):
    pairs = (
        ("WSetA", "PFSetA"),
        ("WSetB", "PFSetB"),
        ("WSetC", "PFSetC"),
    )

    for ied, ap, server, ld in _iter_devices(model):
        for ln in _iter_lns(ld, "DPFW"):
            location = _location(ied, ap, server, ld, ln)

            for w_name, pf_name in pairs:
                w_exists = ln.has_data_object(w_name)
                pf_exists = ln.has_data_object(pf_name)

                if w_exists != pf_exists:
                    missing = pf_name if w_exists else w_name
                    issues.append(
                        _warning(
                            f"DPFW curve point is incomplete: "
                            f"'{missing}' is missing.",
                            location,
                        )
                    )


def check_namespace_semantics(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            if (
                getattr(ln, "ln_class", None) not in CONTROL_LN_CLASSES
                and getattr(ln, "ln_class", None) != "DGEN"
            ):
                continue

            location = _location(ied, ap, server, ld, ln)

            for do in getattr(ln, "data_objects", []):
                data_ns = _get_dai(do, "dataNs")
                if data_ns is None:
                    continue

                value = _normalise(data_ns.value)
                if value and CEI016_NAMESPACE not in value:
                    issues.append(
                        _warning(
                            f"DO '{do.name}' has dataNs='{value}', which "
                            f"does not contain '{CEI016_NAMESPACE}'.",
                            location,
                        )
                    )


def check_qv_consistency(model, issues):
    """
    DPMC and DECP pairs are optional function elements. Once one of the
    corresponding pairs is instantiated, report missing companion instances
    as INFO rather than ERROR.
    """
    for ied, ap, server, ld in _iter_devices(model):
        location = _location(ied, ap, server, ld)

        dpmc = {
            _normalise(getattr(ln, "inst", None))
            for ln in _iter_lns(ld, "DPMC")
        }
        decp = {
            _normalise(getattr(ln, "inst", None))
            for ln in _iter_lns(ld, "DECP")
        }

        if dpmc:
            for expected in ("1", "2"):
                if expected not in dpmc:
                    issues.append(
                        _info(
                            f"DPMC instance {expected} is not present; "
                            "Q(V) lock-in/lock-out may be incomplete.",
                            location,
                        )
                    )

        if decp:
            for expected in ("1", "2"):
                if expected not in decp:
                    issues.append(
                        _info(
                            f"DECP instance {expected} is not present; "
                            "the Q(V) voltage-threshold pair may be incomplete.",
                            location,
                        )
                    )


def check_feature_specific_rules(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln_class in CONTROL_LN_CLASSES:
            for ln in _iter_lns(ld, ln_class):
                location = _location(ied, ap, server, ld, ln)

                # Setpoint functions: configured setpoint objects should have
                # either an instantiated value or a nested value.
                setpoint_dos = {
                    "DWMX": ("WMaxSptPct",),
                    "DAGC": ("WSptPct",),
                    "DVAR": ("VArTgtSptPct",),
                    "DVVR": ("K",),
                    "DPMC": ("WSpt1",),
                    "DFPF": ("PFGnTgtSpt", "PFLodTgtSpt"),
                    "DPFW": (
                        "WSetA", "PFSetA", "WSetB", "PFSetB",
                        "WSetC", "PFSetC", "VLkIn", "VLkOut",
                    ),
                }

                for do_name in setpoint_dos.get(ln_class, ()):
                    do = _get_do(ln, do_name)
                    if do is None:
                        continue

                    values = []
                    for dai in getattr(do, "data_attributes", []):
                        if dai.value not in (None, ""):
                            values.append(dai.value)

                    for sdi in getattr(do, "sub_data_objects", []):
                        for dai in getattr(sdi, "data_attributes", []):
                            if dai.value not in (None, ""):
                                values.append(dai.value)

                    if not values:
                        issues.append(
                            _warning(
                                f"Setpoint DO '{do_name}' is present but "
                                "has no configured value.",
                                location,
                            )
                        )


# ============================================================================
# Public API
# ============================================================================

def analyze_cei016(model):
    issues = []

    # Mandatory model structure
    check_ld_plant(model, issues)
    check_single_logical_device(model, issues)
    check_required_logical_nodes(model, issues)
    check_instantiated_profile(model, issues)

    # Optional functions
    check_optional_logical_nodes(model, issues)

    # IEC 61850 type system / inheritance
    check_lnode_types(model, issues)
    check_instantiated_dos_against_types(model, issues)

    # Semantic and cross-function validation
    check_dgen_semantics(model, issues)
    check_state_values(model, issues)
    check_measurement_structure(model, issues)
    check_control_semantics(model, issues)
    check_feature_specific_rules(model, issues)
    check_dpfw_curve(model, issues)
    check_namespace_semantics(model, issues)
    check_qv_consistency(model, issues)

    return issues


# Backwards-compatible name.
check_cei016 = analyze_cei016


__all__ = [
    "CEI016Issue",
    "REQUIRED_LOGICAL_DEVICE",
    "REQUIRED_LN_CLASSES",
    "OPTIONAL_LN_CLASSES",
    "REQUIRED_DOS",
    "REQUIRED_PATHS",
    "OPTIONAL_DOS",
    "CONTROL_LN_CLASSES",
    "CEI016_NAMESPACE",
    "analyze_cei016",
    "check_cei016",
]
