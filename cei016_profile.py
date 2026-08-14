"""CEI 0-16 V5 profile validation using the effective SCL type model."""

from dataclasses import dataclass
from cei016_observability import OBSERVABILITY_RULES, MANDATORY, CONDITIONAL, OPTIONAL


@dataclass
class CEI016Issue:
    severity: str
    message: str
    location: str = ""
    rule_id: str = ""

    def __str__(self):
        prefix = f"[{self.severity}]"
        if self.rule_id:
            prefix += f" [{self.rule_id}]"
        if self.location:
            return f"{prefix} {self.location}: {self.message}"
        return f"{prefix} {self.message}"


def _error(message, location="", rule_id=""):
    return CEI016Issue("ERROR", message, location, rule_id)


def _warning(message, location="", rule_id=""):
    return CEI016Issue("WARNING", message, location, rule_id)


def _iter_devices(model):
    for ied in getattr(model, "ieds", []):
        for ap in getattr(ied, "access_points", []):
            for server in getattr(ap, "servers", []):
                for ld in getattr(server, "l_devices", []):
                    yield ied, ap, server, ld


def _iter_lns(ld, ln_class=None):
    for ln in getattr(ld, "all_logical_nodes", []):
        if ln_class is None or ln.ln_class == ln_class:
            yield ln


def _location(ied, ap, server, ld, ln=None):
    parts = []
    if getattr(ied, "name", None):
        parts.append(f"IED={ied.name}")
    if getattr(ap, "name", None):
        parts.append(f"AP={ap.name}")
    if getattr(server, "name", None):
        parts.append(f"Server={server.name}")
    parts.append(f"LDevice={getattr(ld, 'name', None) or getattr(ld, 'inst', '')}")
    if ln is not None:
        parts.append(f"LN={ln.identifier}")
    return "/".join(parts)


def _rule_applies(rule, ln):
    if rule.get("prefix") is not None and ln.prefix != rule["prefix"]:
        return False
    if rule.get("inst") is not None and str(ln.inst) != str(rule["inst"]):
        return False
    return True


def _check_observability(model, issues):
    """Validate paths against the effective type model, not only DOI/DAI instances."""
    for ied, ap, server, ld in _iter_devices(model):
        for rule in OBSERVABILITY_RULES:
            ln_class = rule["ln_class"]
            matching = [ln for ln in _iter_lns(ld, ln_class) if _rule_applies(rule, ln)]
            if not matching:
                continue
            for ln in matching:
                location = _location(ied, ap, server, ld, ln)
                path = rule.get("path")
                if path is None:
                    continue
                if ln.has_data_path(path):
                    continue
                if rule["requirement"] == MANDATORY:
                    issues.append(_error(f"Required effective path '{path}' is not defined.", location, rule["id"]))
                elif rule["requirement"] == CONDITIONAL:
                    issues.append(_error(f"Conditionally required effective path '{path}' is not defined.", location, rule["id"]))
                else:
                    issues.append(_warning(f"Optional effective path '{path}' is not defined.", location, rule["id"]))


def _check_ld_plant(model, issues):
    found = []
    for ied, ap, server, ld in _iter_devices(model):
        if getattr(ld, "name", None) == "LD_Plant" or getattr(ld, "inst", None) == "LD_Plant":
            found.append((ied, ap, server, ld))
    if not found:
        issues.append(_error("Required Logical Device 'LD_Plant' was not found.", rule_id="LD-001"))
    elif len(found) > 1:
        issues.append(_error(f"Multiple Logical Devices named 'LD_Plant' found ({len(found)}).", rule_id="LD-002"))


def _check_lln0(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        if ld.ln0 is None:
            issues.append(_error("Required LLN0 is missing.", _location(ied, ap, server, ld), "LN0-001"))


def _check_lnode_types(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            location = _location(ied, ap, server, ld, ln)
            if not ln.ln_type:
                issues.append(_warning("Logical Node has no lnType; effective type checks are unavailable.", location, "TYPE-001"))
                continue
            if model.get_lnode_type(ln.ln_type) is None:
                issues.append(_error(f"LNodeType '{ln.ln_type}' does not exist.", location, "TYPE-002"))
                continue
            try:
                model.resolve_lnode_type(ln.ln_type)
            except ValueError as exc:
                issues.append(_error(str(exc), location, "TYPE-003"))


def _check_doi_against_type(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            if not ln.ln_type:
                continue
            location = _location(ied, ap, server, ld, ln)
            for do in ln.data_objects:
                if not ln.has_defined_data_object(do.name):
                    issues.append(_warning(f"DOI '{do.name}' is instantiated but is not defined by LNodeType '{ln.ln_type}'.", location, "TYPE-004"))


def _effective_value(ln, path):
    """Return configured value when the requested path is physically instantiated."""
    parts = path.split(".")
    if not parts:
        return None
    current = ln.get_data_object(parts[0])
    if current is None:
        return None
    for index, part in enumerate(parts[1:]):
        if index == len(parts[1:]) - 1:
            dai = current.get_data_attribute(part)
            return dai.value if dai else None
        current = current.get_sub_data_object(part)
        if current is None:
            return None
    return None


def _check_dgen_semantics(model, issues):
    for ied, ap, server, ld in _iter_devices(model):
        seen_inst = set()
        seen_ids = set()
        for ln in _iter_lns(ld, "DGEN"):
            location = _location(ied, ap, server, ld, ln)
            inst_key = (ln.prefix, ln.inst)
            if inst_key in seen_inst:
                issues.append(_warning(f"Duplicate DGEN prefix/inst '{ln.prefix}/{ln.inst}'.", location, "DGEN-001"))
            seen_inst.add(inst_key)
            value = _effective_value(ln, "GnGrId.stVal")
            if value in (None, ""):
                continue
            try:
                n = int(str(value).strip())
            except ValueError:
                issues.append(_warning(f"GnGrId.stVal='{value}' is not numeric.", location, "DGEN-002"))
                continue
            if n <= 0:
                issues.append(_error("GnGrId.stVal must be a positive integer.", location, "DGEN-003"))
            if n in seen_ids:
                issues.append(_warning(f"Duplicate GnGrId.stVal '{n}'.", location, "DGEN-004"))
            seen_ids.add(n)


def _check_control_configuration(model, issues):
    control_classes = {"DWMX", "DAGC", "DVAR", "DFPF", "DVVR", "DPMC", "DPFW"}
    for ied, ap, server, ld in _iter_devices(model):
        for ln in getattr(ld, "all_logical_nodes", []):
            if ln.ln_class not in control_classes:
                continue
            location = _location(ied, ap, server, ld, ln)
            for do in ln.data_objects:
                for name in ("ctlModel", "sboTimeout", "operTimeout"):
                    dai = do.get_data_attribute(name)
                    if dai is None:
                        continue
                    if name == "ctlModel" and dai.value in (None, ""):
                        issues.append(_warning(f"DO '{do.name}' has an empty ctlModel.", location, "CTRL-001"))
                    if name in ("sboTimeout", "operTimeout") and dai.value not in (None, ""):
                        try:
                            if int(str(dai.value).strip()) < 0:
                                issues.append(_warning(f"DO '{do.name}' has negative {name}={dai.value}.", location, "CTRL-002"))
                        except ValueError:
                            issues.append(_warning(f"DO '{do.name}' has non-numeric {name}='{dai.value}'.", location, "CTRL-003"))


def analyze_cei016(model):
    issues = []
    _check_ld_plant(model, issues)
    _check_lln0(model, issues)
    _check_lnode_types(model, issues)
    _check_doi_against_type(model, issues)
    _check_observability(model, issues)
    _check_dgen_semantics(model, issues)
    _check_control_configuration(model, issues)
    return issues


check_cei016 = analyze_cei016

__all__ = ["CEI016Issue", "analyze_cei016", "check_cei016"]
