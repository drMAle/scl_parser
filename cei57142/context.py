"""CEI 57-142 context helpers."""
GENERATION_PREFIXES={"GenPV","GenWi","GenTer","GenIdr"}

def all_lnodes(model):
    for ied in getattr(model,"ieds",[]):
        for ap in getattr(ied,"access_points",[]):
            for server in getattr(ap,"servers",[]):
                for ld in getattr(server,"l_devices",[]):
                    if getattr(ld,"ln0",None): yield ld,ld.ln0
                    for ln in getattr(ld,"logical_nodes",[]): yield ld,ln

def find_lns(model, ln_class=None, prefix=None, inst=None):
    out=[]
    for ld,ln in all_lnodes(model):
        if getattr(ld,"inst",None)!="LD_Plant": continue
        if ln_class is not None and getattr(ln,"ln_class",None)!=ln_class: continue
        if prefix is not None and getattr(ln,"prefix","")!=prefix: continue
        if inst is not None and str(getattr(ln,"inst",""))!=str(inst): continue
        out.append(ln)
    return out

def detect_context(model):
    p={getattr(ln,"prefix","") for ld,ln in all_lnodes(model) if getattr(ld,"inst",None)=="LD_Plant"}
    return {"generation_present":bool(p & GENERATION_PREFIXES),
            "storage_present":"St" in p,
            "generation_source_present":bool(p & GENERATION_PREFIXES),
            "generation_group_present":any(getattr(ln,"ln_class","")== "DGEN" and getattr(ln,"prefix","")=="SSGG"
                                          for ld,ln in all_lnodes(model) if getattr(ld,"inst",None)=="LD_Plant")}

def plant_ldevices(model):
    return [ld for ld,ln in all_lnodes(model) if getattr(ld,"inst",None)=="LD_Plant"]
