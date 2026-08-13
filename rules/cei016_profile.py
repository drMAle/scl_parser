"""
CEI 0-16 V5 profile checker for the IEC 61850 SCL parser.

This module is intentionally independent from the GUI.

Usage:

    from cei016_profile import analyze_cei016

    issues = analyze_cei016(model)

Each issue has:
    severity   -> "ERROR" or "WARNING"
    message
    location

The checker validates the CEI 0-16 V5 minimum profile discussed for this
project. It checks instantiated Logical Nodes and their DOI/DAI/SDI
structure, while also using the parser's resolved LNodeType information
(including inherited definitions).
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
# CEI 0-16 profile definition
# ============================================================================

# Required DOs when the corresponding LN/function is instantiated.
REQUIRED_DOS = {
    "LPHD": (
        "PhyNam",
    ),

    "DPCC": (
        "WRtg",
        "VArRtg",
        "VARtg",
    ),

    "DECP": (
        "Beh",
    ),

    "DGEN": (
        "Beh",
        "Health",
        "GnGrId",
    ),

    "DSTO": (
        "Beh",
    ),

    "XCBR": (
        "Pos",
    ),

    "MMXU": (
        "TotW",
        "TotVAr",
        "PPV",
    ),

    "DWMX": (
        "Beh",
        "Health",
        "WMaxSptPct",
        "Mod",
        "FctOpStAuto",
        "FctOpStEx",
    ),

    "DAGC": (
        "Beh",
        "Health",
        "WSptPct",
        "Mod",
        "FctOpSt",
    ),

    "DVAR": (
        "Beh",
        "Health",
        "VArTgtSptPct",
        "Mod",
        "FctOpSt",
    ),

    "DFPF": (
        "Beh",
        "Health",
        "PFGnTgtSpt",
        "PFLodTgtSpt",
        "Mod",
        "FctOpSt",
    ),

    "DVVR": (
        "Beh",
        "Health",
        "Mod",
        "FctOpSt",
        "K",
    ),

    "DPMC": (
        "WSpt1",
    ),

    "DPFW": (
        "Beh",
        "Health",
        "Mod",
        "FctOpSt",
        "WSetA",
        "PFSetA",
        "WSetB",
        "PFSetB",
        "WSetC",
        "PFSetC",
        "VLkIn",
        "VLkOut",
    ),
}


# Required instantiated DOI/SDI/DAI paths.
#
# A path is interpreted as:
#   DO.DAI
#   DO.SDI.DAI
#
# A final bare DO name means that the DOI itself must exist.
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

    "DECP": (
        "Beh.stVal",
    ),

    "DGEN": (
        "Beh.stVal",
        "Health.stVal",
        "GnGrId.stVal",
    ),

    "DSTO": (
        "Beh.stVal",
    ),

    "XCBR": (
        "Pos.stVal",
    ),

    "MMXU": (
        "TotW.mag",
        "TotVAr.mag",
        "PPV.mag",
    ),

    "DWMX": (
        "Beh.stVal",
        "Health.stVal",
        "WMaxSptPct.mxVal.f",
        "Mod.stVal",
        "FctOpStAuto.stVal",
        "FctOpStEx.stVal",
    ),

    "DAGC": (
        "Beh.stVal",
        "Health.stVal",
        "WSptPct.mxVal.f",
        "Mod.stVal",
        "FctOpSt.stVal",
    ),

    "DVAR": (
        "Beh.stVal",
        "Health.stVal",
        "VArTgtSptPct.mxVal.f",
        "Mod.stVal",
        "FctOpSt.stVal",
    ),

    "DFPF": (
        "Beh.stVal",
        "Health.stVal",
        "PFGnTgtSpt",
        "PFLodTgtSpt",
        "Mod.stVal",
        "FctOpSt.stVal",
    ),

    "DVVR": (
        "Beh.stVal",
        "Health.stVal",
        "Mod.stVal",
        "FctOpSt.stVal",
        "K.setMag",
    ),

    "DPMC": (
        "WSpt1.ctlVal",
    ),

    "DPFW": (
        "Beh.stVal",
        "Health.stVal",
        "Mod.stVal",
        "FctOpSt.stVal",
        "WSetA",
        "PFSetA",
        "WSetB",
        "PFSetB",
        "WSetC",
        "PFSetC",
        "VLkIn",
        "VLkOut",
    ),
}


# Optional DOs from the project profile.
OPTIONAL_DOS = {
    "MMXU": (
        "A",
    ),
}


CONTROL_LN_CLASSES = (
    "DWMX",
    "DAGC",
    "DVAR",
    "DFPF",
    "DVVR",
    "DPMC",
    "DPFW",
)


# ============================================================================
# Generic helpers
# ============================================================================

def _error(message, location=""):
    return CEI016Issue("ERROR", message, location)


def _warning(message, location=""):
    return CEI016Issue("WARNING", message, location)


def _iter_devices(model):
    """Yield (IED, AccessPoint, Server, LDevice)."""
    for ied in getattr(model, "ieds", []):
        for access_point in getattr(ied, "access_points", []):
            for server in getattr(access_point, "servers", []):
                for l_device in getattr(server, "l_devices", []):
                    yield ied, access_point, server, l_device


def _iter_lns(l_device, ln_class=None):
    """
    Use the all_logical_nodes property implemented by the supplied parser.
    """
    for ln in getattr(l_device, "all_logical_nodes", []):
        if ln_class is None or ln.ln_class == ln_class:
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
        parts.append(f"LN={ln.identifier}")

    return "/".join(parts)


def _get_do(ln, name):
    return ln.get_data_object(name)


def _get_dai(data_object, name):
    return data_object.get_data_attribute(name)


def _get_sdi(data_object, name):
    return data_object.get_sub_data_object(name)


def _resolve_path(ln, path):
    """
    Resolve an instantiated DOI/SDI/DAI path.

    Examples:
        Beh.stVal
        WRtg.setMag
        WMaxSptPct.mxVal.f
    """
    parts = path.split(".")

    if not parts:
        return None

    current = _get_do(ln, parts[0])

    if current is None:
        return None

    for index, part in enumerate(parts[1:]):
        is_last = index == len(parts[1:]) - 1

        if is_last:
            return _get_dai(current, part)

        current = _get_sdi(current, part)

        if current is None:
            return None

    return current


def _value(ln, path):
    item = _resolve_path(ln, path)

    if item is None:
        return None

    return getattr(item, "value", None)


def _check_do(ln, do_name, issues, location):
    if not ln.has_data_object(do_name):
        issues.append(
            _error(
                f"Required DO '{do_name}' is missing.",
                location,
            )
        )


def _check_path(ln, path, issues, location):
    if _resolve_path(ln, path) is None:
        issues.append(
            _error(
                f"Required path '{path}' is missing.",
                location,
            )
        )


# ============================================================================
# Basic structure
# ============================================================================

def check_ld_plant(model, issues):
    """
    The CEI profile for this project uses a single Logical Device named
    LD_Plant.
    """
    found = []

    for ied, ap, server, ld in _iter_devices(model):
        if getattr(ld, "name", None) == "LD_Plant":
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
                f"Multiple Logical Devices named 'LD_Plant' found "
                f"({len(found)})."
            )
        )


def check_single_logical_device(model, issues):
    for ied in getattr(model, "ieds", []):
        count = 0

        for ap in getattr(ied, "access_points", []):
            for server in getattr(ap, "servers", []):
                count += len(getattr(server, "l_devices", []))

        if count > 1:
            issues.append(
                _warning(
                    f"IED contains {count} Logical Devices. "
                    "The CEI 0-16 plant profile expects the model "
                    "to be contained in LD_Plant.",
                    f"IED={getattr(ied, 'name', '')}",
                )
            )


def check_lln0(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        if ld.ln0 is None:
            issues.append(
                _error(
                    "Required LLN0 is missing.",
                    _location(ied, ap, server, ld),
                )
            )


def check_lphd(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        lns = list(_iter_lns(ld, "LPHD"))

        if not lns:
            issues.append(
                _error(
                    "Required LPHD Logical Node is missing.",
                    _location(ied, ap, server, ld),
                )
            )
            continue

        for ln in lns:
            location = _location(ied, ap, server, ld, ln)

            for do_name in REQUIRED_DOS["LPHD"]:
                _check_do(ln, do_name, issues, location)

            for path in REQUIRED_PATHS["LPHD"]:
                _check_path(ln, path, issues, location)


# ============================================================================
# Generic LN profile checks
# ============================================================================

def check_instantiated_profile(model, issues):
    """
    For every CEI function actually instantiated in the SCL, verify its
    mandatory DOs and mandatory DOI/SDI/DAI paths.
    """
    for ied, ap, server, ld in _iter_devices(model):
        for ln_class, do_names in REQUIRED_DOS.items():

            for ln in _iter_lns(ld, ln_class):
                location = _location(ied, ap, server, ld, ln)

                for do_name in do_names:
                    _check_do(
                        ln,
                        do_name,
                        issues,
                        location,
                    )

                for path in REQUIRED_PATHS.get(ln_class, ()):
                    _check_path(
                        ln,
                        path,
                        issues,
                        location,
                    )


# ============================================================================
# Type system / inheritance
# ============================================================================

def check_lnode_types(model, issues):
    """
    Verify that each LN with an lnType references an existing LNodeType and
    that its inheritance chain can be resolved.
    """
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):

            location = _location(ied, ap, server, ld, ln)
            ln_type = getattr(ln, "ln_type", None)

            if not ln_type:
                issues.append(
                    _warning(
                        "Logical Node has no lnType.",
                        location,
                    )
                )
                continue

            if model.get_lnode_type(ln_type) is None:
                issues.append(
                    _error(
                        f"LNodeType '{ln_type}' referenced by the "
                        "Logical Node does not exist.",
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
    """
    Check that instantiated DOI names are present in the resolved LNodeType,
    including inherited DO definitions.
    """
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
# DGEN consistency
# ============================================================================

def check_dgen(model, issues):
    """
    Additional consistency checks for DGEN instances and GnGrId.
    """
    for ied, ap, server, ld in _iter_devices(model):

        seen_instances = set()
        seen_group_ids = set()

        for ln in _iter_lns(ld, "DGEN"):
            location = _location(ied, ap, server, ld, ln)

            inst = getattr(ln, "inst", None)

            if inst in seen_instances:
                issues.append(
                    _warning(
                        f"Duplicate DGEN inst '{inst}'.",
                        location,
                    )
                )

            seen_instances.add(inst)

            group_id = _value(ln, "GnGrId.stVal")

            if group_id in (None, ""):
                continue

            try:
                numeric_id = int(str(group_id).strip())

                if numeric_id <= 0:
                    issues.append(
                        _error(
                            "GnGrId.stVal must be a positive integer.",
                            location,
                        )
                    )

                if numeric_id in seen_group_ids:
                    issues.append(
                        _warning(
                            f"Duplicate GnGrId.stVal '{numeric_id}'.",
                            location,
                        )
                    )

                seen_group_ids.add(numeric_id)

            except ValueError:
                issues.append(
                    _warning(
                        f"GnGrId.stVal='{group_id}' is not numeric.",
                        location,
                    )
                )


# ============================================================================
# Control DO checks
# ============================================================================

def check_control_attributes(model, issues):
    """
    Basic consistency checks for instantiated control attributes.

    This does not force a single ctlModel value for every function, because
    the exact control model is an engineering/configuration choice. It does
    detect empty or malformed timeout values when the attributes exist.
    """
    for ied, ap, server, ld in _iter_devices(model):

        for ln_class in CONTROL_LN_CLASSES:
            for ln in _iter_lns(ld, ln_class):

                location = _location(ied, ap, server, ld, ln)

                for do in getattr(ln, "data_objects", []):

                    ctl_model = do.get_data_attribute("ctlModel")

                    if ctl_model is not None:
                        if ctl_model.value in (None, ""):
                            issues.append(
                                _warning(
                                    f"DO '{do.name}' has an empty ctlModel.",
                                    location,
                                )
                            )

                    for timeout_name in (
                        "sboTimeout",
                        "operTimeout",
                    ):
                        timeout = do.get_data_attribute(timeout_name)

                        if timeout is None:
                            continue

                        value = timeout.value

                        if value in (None, ""):
                            issues.append(
                                _warning(
                                    f"DO '{do.name}' has an empty "
                                    f"{timeout_name}.",
                                    location,
                                )
                            )
                            continue

                        try:
                            numeric = int(str(value).strip())

                            if numeric < 0:
                                issues.append(
                                    _warning(
                                        f"DO '{do.name}' has negative "
                                        f"{timeout_name}={value}.",
                                        location,
                                    )
                                )
                        except ValueError:
                            issues.append(
                                _warning(
                                    f"DO '{do.name}' has non-numeric "
                                    f"{timeout_name}='{value}'.",
                                    location,
                                )
                            )



# ============================================================================
# Semantic / consistency checks
# ============================================================================

def _normalise_value(value):
    if value is None:
        return None
    return str(value).strip()


def _check_allowed_value(ln, path, allowed, issues, location, label=None):
    value = _normalise_value(_value(ln, path))
    if value is None:
        return

    if value not in allowed:
        label = label or path
        issues.append(
            _warning(
                f"{label} has value '{value}', expected one of: "
                f"{', '.join(sorted(str(x) for x in allowed))}.",
                location,
            )
        )


def check_semantic_states(model, issues):
    """Check common CEI state/enumeration values."""
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            location = _location(ied, ap, server, ld, ln)

            if ln.ln_class in (
                "DECP", "DGEN", "DSTO", "DWMX", "DAGC",
                "DVAR", "DFPF", "DVVR", "DPMC", "DPFW",
            ):
                _check_allowed_value(
                    ln, "Beh.stVal",
                    {"on", "off", "blocked", "test", "test/blocked",
                     "on-blocked", "off-blocked", "inactive"},
                    issues, location, "Beh.stVal",
                )

            if ln.ln_class == "DGEN":
                _check_allowed_value(
                    ln, "Health.stVal",
                    {"Ok", "Warning", "Alarm", "Failure",
                     "Non-operational"},
                    issues, location, "Health.stVal",
                )

            if ln.ln_class in (
                "DWMX", "DAGC", "DVAR", "DFPF", "DVVR", "DPFW"
            ):
                _check_allowed_value(
                    ln, "Mod.stVal",
                    {"on", "off", "blocked", "test", "test/blocked",
                     "inactive"},
                    issues, location, "Mod.stVal",
                )


def check_dgen_identity(model, issues):
    """Check DGEN.inst, prefix and GnGrId consistency."""
    for ied, ap, server, ld in _iter_devices(model):
        for ln in _iter_lns(ld, "DGEN"):
            location = _location(ied, ap, server, ld, ln)

            inst = _normalise_value(getattr(ln, "inst", None))
            prefix = _normalise_value(getattr(ln, "prefix", ""))

            if prefix and prefix not in ("SSGG", "DGEN"):
                issues.append(
                    _warning(
                        f"DGEN has unexpected prefix '{prefix}'. "
                        "The project profile uses 'SSGG' for generator groups.",
                        location,
                    )
                )

            group_id = _normalise_value(_value(ln, "GnGrId.stVal"))

            if inst is not None and group_id is not None:
                try:
                    if int(inst) != int(group_id):
                        issues.append(
                            _warning(
                                f"DGEN inst='{inst}' is inconsistent with "
                                f"GnGrId.stVal='{group_id}'.",
                                location,
                            )
                        )
                except ValueError:
                    pass


def check_measurement_structure(model, issues):
    """Check MMXU measurement DOs for the expected mag structure."""
    for ied, ap, server, ld in _iter_devices(model):
        for ln in _iter_lns(ld, "MMXU"):
            location = _location(ied, ap, server, ld, ln)

            for do_name in ("TotW", "TotVAr", "PPV"):
                do = _get_do(ln, do_name)
                if do is None:
                    continue

                if (_get_sdi(do, "mag") is None and
                        _get_dai(do, "mag") is None):
                    issues.append(
                        _warning(
                            f"MMXU DO '{do_name}' exists but has no "
                            "'mag' measurement attribute.",
                            location,
                        )
                    )

            if ln.has_data_object("A"):
                do = _get_do(ln, "A")
                if (_get_sdi(do, "mag") is None and
                        _get_dai(do, "mag") is None):
                    issues.append(
                        _warning(
                            "Optional MMXU DO 'A' is present but has no "
                            "'mag' measurement attribute.",
                            location,
                        )
                    )


def check_control_semantics(model, issues):
    """Check basic consistency of control setpoints and ctlModel."""
    setpoint_paths = {
        "DWMX": ("WMaxSptPct.mxVal.f",),
        "DAGC": ("WSptPct.mxVal.f",),
        "DVAR": ("VArTgtSptPct.mxVal.f",),
        "DVVR": ("K.setMag",),
        "DPMC": ("WSpt1.ctlVal",),
    }

    for ied, ap, server, ld in _iter_devices(model):
        for ln_class, paths in setpoint_paths.items():
            for ln in _iter_lns(ld, ln_class):
                location = _location(ied, ap, server, ld, ln)

                for path_name in paths:
                    item = _resolve_path(ln, path_name)
                    if item is None:
                        continue

                    value = _normalise_value(getattr(item, "value", None))
                    if value is None or value == "":
                        issues.append(
                            _warning(
                                f"Control setpoint '{path_name}' is present "
                                "but has no configured value.",
                                location,
                            )
                        )

                for do in getattr(ln, "data_objects", []):
                    ctl_model = do.get_data_attribute("ctlModel")
                    st_val = do.get_data_attribute("stVal")

                    if ctl_model is not None and st_val is None:
                        issues.append(
                            _warning(
                                f"Control DO '{do.name}' has ctlModel but "
                                "no stVal.",
                                location,
                            )
                        )


def check_dpfw_curve(model, issues):
    """Check structural consistency of DPFW curve points."""
    curve_pairs = (
        ("WSetA", "PFSetA"),
        ("WSetB", "PFSetB"),
        ("WSetC", "PFSetC"),
    )

    for ied, ap, server, ld in _iter_devices(model):
        for ln in _iter_lns(ld, "DPFW"):
            location = _location(ied, ap, server, ld, ln)

            for w_name, pf_name in curve_pairs:
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
    """Check CEI-016 dataNs markers when they are explicitly present."""
    cei_marker = "IEC 61850-CEI016:2025"

    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            location = _location(ied, ap, server, ld, ln)

            if ln.ln_class not in CONTROL_LN_CLASSES and ln.ln_class != "DGEN":
                continue

            for do in getattr(ln, "data_objects", []):
                data_ns = do.get_data_attribute("dataNs")
                if data_ns is None:
                    continue

                value = _normalise_value(data_ns.value)
                if value and cei_marker not in value:
                    issues.append(
                        _warning(
                            f"DO '{do.name}' has dataNs='{value}', "
                            f"which does not contain '{cei_marker}'.",
                            location,
                        )
                    )


def check_cross_function_consistency(model, issues):
    """
    Check paired Q(V) configuration.

    If DPMC or DECP are used, the project profile expects instances 1 and 2.
    Missing members are informational because the function itself is optional.
    """
    for ied, ap, server, ld in _iter_devices(model):
        location = _location(ied, ap, server, ld)

        dpmc = {
            _normalise_value(getattr(ln, "inst", None))
            for ln in _iter_lns(ld, "DPMC")
        }
        decp = {
            _normalise_value(getattr(ln, "inst", None))
            for ln in _iter_lns(ld, "DECP")
        }

        if dpmc:
            for expected in ("1", "2"):
                if expected not in dpmc:
                    issues.append(
                        _info(
                            f"DPMC instance {expected} is not present; "
                            "Q(V) lock-in/lock-out configuration may be incomplete.",
                            location,
                        )
                    )

        if decp:
            for expected in ("1", "2"):
                if expected not in decp:
                    issues.append(
                        _info(
                            f"DECP instance {expected} is not present; "
                            "the paired Q(V) voltage threshold may be incomplete.",
                            location,
                        )
                    )


# ============================================================================
# Public API
# ============================================================================

def analyze_cei016(model):
    """
    Run the complete CEI 0-16 V5 analysis.

    Returns:
        list[CEI016Issue]
    """
    issues = []

    # Basic model structure
    check_ld_plant(model, issues)
    check_single_logical_device(model, issues)
    check_lln0(model, issues)
    check_lphd(model, issues)

    # CEI LN / DO / DA profile
    check_instantiated_profile(model, issues)

    # Type system and inheritance
    check_lnode_types(model, issues)
    check_instantiated_dos_against_types(model, issues)

    # Additional semantic consistency
    check_dgen(model, issues)
    check_control_attributes(model, issues)

    # Semantic / cross-function checks
    check_semantic_states(model, issues)
    check_dgen_identity(model, issues)
    check_measurement_structure(model, issues)
    check_control_semantics(model, issues)
    check_dpfw_curve(model, issues)
    check_namespace_semantics(model, issues)
    check_cross_function_consistency(model, issues)

    return issues


# Backwards-compatible name.
check_cei016 = analyze_cei016


__all__ = [
    "CEI016Issue",
    "REQUIRED_DOS",
    "REQUIRED_PATHS",
    "OPTIONAL_DOS",
    "CONTROL_LN_CLASSES",
    "analyze_cei016",
    "check_cei016",
    "check_semantic_states",
    "check_dgen_identity",
    "check_measurement_structure",
    "check_control_semantics",
    "check_dpfw_curve",
    "check_namespace_semantics",
    "check_cross_function_consistency",
]
