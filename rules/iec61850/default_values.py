"""Semantic checks for default values explicitly observed in MMS ReadResponse.

This module is intentionally independent from SCL/discovery validation. It uses
only Read/ReadResponse traffic decoded by the PCAP model and never invents a
missing value.
"""
from __future__ import annotations

import re
from collections import defaultdict
from analyzer.result import Issue

# Order of the status Data Objects in the corresponding $ST structure.  This
# mirrors the CEI 0-16 profile used by this project.  Only positions needed by
# the default-value rules are relevant, but retaining the complete status order
# makes the positional mapping explicit and auditable.
ST_DO_ORDER = {
    "LLN0": ("Beh", "Health", "Mod"),
    "DECP": ("Beh",),
    "DGEN": ("Beh", "Health", "GnGrId"),
    "DSTO": ("Beh",),
    "DWMX": ("Beh", "Health", "Mod", "FctOpStAuto", "FctOpStEx"),
    "DAGC": ("Beh", "Health", "Mod", "FctOpSt"),
    "DVAR": ("Beh", "Health", "Mod", "FctOpSt"),
    "DFPF": ("Beh", "Health", "Mod", "FctOpSt"),
    "DVVR": ("Beh", "Health", "Mod", "FctOpSt"),
    "DPFW": ("Beh", "Health", "Mod", "FctOpSt"),
}

_TARGETS = {"Health", "Beh", "Mod"}


def _ln_class(ln_name: str) -> str | None:
    if ln_name == "LLN0":
        return "LLN0"
    # Match the longest known class embedded before the numeric instance.
    candidates = sorted((c for c in ST_DO_ORDER if c != "LLN0"), key=len, reverse=True)
    for cls in candidates:
        if re.search(re.escape(cls) + r"\d+$", ln_name):
            return cls
    return None


def _extract_status_stvals(read_values: list[dict]) -> list[int]:
    """Extract stVal candidates from explicit status structures.

    A status structure in this capture is encoded as integer stVal followed by
    quality (bit-string) and timestamp (UTC-time).  We deliberately require
    that local pattern instead of collecting arbitrary integers from a larger
    structure, avoiding false positives from unrelated DAs.
    """
    values: list[int] = []
    for i, item in enumerate(read_values):
        if item.get("type") != "integer" or not isinstance(item.get("value"), int):
            continue
        nxt = read_values[i + 1 : i + 3]
        if len(nxt) == 2 and nxt[0].get("type") == "bit-string" and nxt[1].get("type") == "utc-time":
            values.append(item["value"])
    return values


def _observed_status_values(model) -> dict[str, dict[str, tuple[int, object]]]:
    """Return observed target stVals keyed by LN and DO.

    Only correlated Read request/response pairs are used.  For a response to
    an $ST variable, values are mapped by the explicit status-DO order above.
    """
    requests = {
        (m.invoke_id, m.direction): m
        for m in model.mms_messages
        if m.service == "read" and m.object_name and m.object_name.endswith("$ST")
    }
    responses = [
        m for m in model.mms_messages
        if m.service == "read" and m.object_name and m.object_name.endswith("$ST") and m.read_values
    ]

    out: dict[str, dict[str, tuple[int, object]]] = defaultdict(dict)
    for response in responses:
        # Find the request with the same invoke ID and reverse direction.  This
        # is intentionally correlation-only; the value still comes exclusively
        # from the response.
        req = None
        for candidate in requests.values():
            if candidate.invoke_id != response.invoke_id:
                continue
            a, b = candidate.direction.split(" -> ")
            c, d = response.direction.split(" -> ")
            if a == d and b == c:
                req = candidate
                break
        if req is None:
            continue

        item = response.object_name.split("/", 1)[-1]
        ln_name, _, fc = item.partition("$")
        if fc != "ST":
            continue
        cls = _ln_class(ln_name)
        if cls is None:
            continue
        order = ST_DO_ORDER[cls]
        stvals = _extract_status_stvals(response.read_values)
        for idx, value in enumerate(stvals[: len(order)]):
            do_name = order[idx]
            if do_name in _TARGETS:
                out[ln_name][do_name] = (value, response)
    return out


def check_default_values(model) -> list[Issue]:
    """Validate Health.stVal, Beh.stVal and Mod.stVal from observed Read data."""
    observed = _observed_status_values(model)
    issues: list[Issue] = []

    for ln_name in sorted(observed):
        values = observed[ln_name]
        cls = _ln_class(ln_name) or ""
        location_base = f"{model.filename.name}:{ln_name}"

        if "Health" in values:
            value, _ = values["Health"]
            loc = f"{location_base}.Health.stVal"
            if value != 1:
                issues.append(Issue("ERROR", "DEF-HEALTH-001", "", loc,
                                    f"Observed Health.stVal={value}; expected 1."))

        for name in ("Beh", "Mod"):
            if name not in values:
                continue
            value, _ = values[name]
            loc = f"{location_base}.{name}.stVal"
            if value not in (-1, -5):
                issues.append(Issue("ERROR", f"DEF-{name.upper()}-001", "", loc,
                                    f"Observed {name}.stVal={value}; expected -1 or -5."))

        if "Beh" in values and "Mod" in values:
            beh = values["Beh"][0]
            mod = values["Mod"][0]
            if beh != mod:
                loc = f"{location_base}.Beh.stVal / {ln_name}.Mod.stVal"
                issues.append(Issue("ERROR", "DEF-BEH-MOD-001", "", loc,
                                    f"Observed Beh.stVal={beh} and Mod.stVal={mod}; values must be equal."))

    return issues
