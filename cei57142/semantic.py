"""SCL-provable CEI 57-142 semantic checks."""
from .context import find_lns

def _val(ln,do_name,da_name):
    do=ln.get_data_object(do_name) if hasattr(ln,"get_data_object") else None
    if not do:return None
    for da in getattr(do,"data_attributes",[]):
        if getattr(da,"name",None)==da_name:
            e=getattr(da,"element",None)
            if e is not None:
                for c in list(e):
                    if str(c.tag).endswith("Val"): return c.text
    return None

def _num(v):
    try:return float(v)
    except:return None

def validate_semantics(model):
    out=[]
    for ln in find_lns(model,"DPFW","PFW","1"):
        for do,lo,hi in [("WSetA",0,None),("WSetB",0,None),("WSetC",0,None),
                         ("PFSetA",-1,1),("PFSetB",-1,1),("PFSetC",-1,1),
                         ("VLkIn",1,1.10),("VLkOut",.90,1)]:
            v=_num(_val(ln,do,"setMag"))
            if v is not None and (v<lo or (hi is not None and v>hi)):
                out.append({"severity":"ERROR","rule_id":"CEI57142-SEM-DPFW",
                            "clause":"4.3.1.2.6","category":"semantic","location":ln.identifier,
                            "description":f"{do}.setMag={v} outside CEI 57-142 range [{lo}, {hi}]."})
    for ln in find_lns(model,"DVVR","VArV","1"):
        v=_num(_val(ln,"K","setMag"))
        if v is not None and not -1<=v<=1:
            out.append({"severity":"ERROR","rule_id":"CEI57142-SEM-QV-K","clause":"4.3.1.2.5",
                        "category":"semantic","location":ln.identifier,"description":f"K.setMag={v} outside [-1,1]."})
    for ln in find_lns(model,"DGEN","SSGG"):
        v=_num(_val(ln,"GnGrId","stVal"))
        if v is not None and not 1<=v<=99:
            out.append({"severity":"ERROR","rule_id":"CEI57142-SEM-GNGRID","clause":"4.3.1.1.9",
                        "category":"semantic","location":ln.identifier,"description":f"GnGrId.stVal={v} outside [1,99]."})
    return out
