"""PF1 Observability validator for CEI 57-142:2026."""
from .matrix import OBSERVABILITY_RULES
from .context import find_lns, detect_context, plant_ldevices

def _has_path(ln, do_name, da_name):
    do=ln.get_data_object(do_name) if hasattr(ln,"get_data_object") else None
    if do is None: return False
    if not da_name: return True
    return any(getattr(da,"name",None)==da_name for da in getattr(do,"data_attributes",[]))

def _finding(r, sev, msg, ln=None):
    return {"severity":sev,"rule_id":r.rule_id,"clause":r.clause,
            "category":r.category,"location":getattr(ln,"identifier","LD_Plant"),
            "description":msg}

def validate_observability(model):
    out=[]; ctx=detect_context(model)
    lds=plant_ldevices(model)
    if not lds:
        return [_finding(OBSERVABILITY_RULES[0],"ERROR","LD_Plant is missing.")]
    if len(lds)>1:
        out.append({"severity":"ERROR","rule_id":"CEI57142-OBS-000B","clause":"4.3.1",
                    "category":"structure","location":"SCL",
                    "description":"More than one LD_Plant found; CEI 57-142 specifies one Logical Device."})
    for r in OBSERVABILITY_RULES:
        if r.condition and not ctx.get(r.condition,False): continue
        if r.ln_class=="LLN0":
            lns=find_lns(model,"LLN0")
        elif r.prefix=="SGG":
            lns=find_lns(model,"MMXU","SGG")
        elif r.prefix=="SSGG":
            lns=find_lns(model,"DGEN","SSGG")
        elif r.prefix is None and r.ln_class=="MMXU":
            lns=[x for x in find_lns(model,"MMXU") if getattr(x,"prefix","") in {"GenPV","GenWi","GenTer","GenIdr"}]
        else:
            lns=find_lns(model,r.ln_class,r.prefix,r.inst)
        if not lns:
            sev="WARNING" if r.presence=="O" else "ERROR"
            out.append(_finding(r,sev,f"Missing {r.ln_class} {r.prefix or ''}{r.inst or ''} ({r.description})."))
            continue
        for ln in lns:
            if not _has_path(ln,r.do,r.da):
                sev="WARNING" if r.presence=="O" else "ERROR"
                out.append(_finding(r,sev,f"Missing {r.do}.{r.da or ''} in {ln.identifier}.",ln))
    return out
