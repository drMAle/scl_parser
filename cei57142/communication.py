"""SCL-level communication evidence checks."""
def _elements(model,name):
    root=getattr(model,"root",None)
    return [] if root is None else [e for e in root.iter() if str(e.tag).endswith(name)]

def validate_communication(model):
    out=[]
    if not _elements(model,"DataSet"):
        out.append({"severity":"WARNING","rule_id":"CEI57142-COM-001","clause":"4.3.1/Table 22",
                    "category":"communication","location":"LD_Plant",
                    "description":"No DataSet found. Dataset naming/configuration is project-specific."})
    if not _elements(model,"ReportControl"):
        out.append({"severity":"WARNING","rule_id":"CEI57142-COM-002","clause":"4.3.1/Table 22",
                    "category":"communication","location":"LD_Plant",
                    "description":"No ReportControl found. Exact reporting configuration is project-specific."})
    return out
