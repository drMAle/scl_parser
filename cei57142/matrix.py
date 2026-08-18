"""CEI 57-142:2026 PF1 Observability matrix."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Rule:
    rule_id: str
    clause: str
    ln_class: str
    prefix: str|None
    inst: str|None
    do: str|None
    da: str|None
    presence: str
    category: str
    description: str
    condition: str|None = None
    period_s: int|None = None

OBSERVABILITY_RULES = [
Rule("CEI57142-OBS-001","4.3.1.1.1","LLN0",None,None,None,None,"M","structure","LLN0 in LD_Plant"),
Rule("CEI57142-OBS-002","4.3.1.1.2","LPHD",None,"1","PhyNam","vendor","M","device","CCI manufacturer"),
Rule("CEI57142-OBS-003","4.3.1.1.2","LPHD",None,"1","PhyNam","swRev","M","device","CCI software revision"),
Rule("CEI57142-OBS-004","4.3.1.1.2","LPHD",None,"1","PhyNam","location","M","device","POD identifier"),
Rule("CEI57142-OBS-010","4.3.1.1.3","DPCC","PdC_Wi","1","WRtg","setMag","R","plant","Maximum active power injection"),
Rule("CEI57142-OBS-011","4.3.1.1.3","DPCC","PdC_Wa","1","WRtg","setMag","R","plant","Maximum active power absorption"),
Rule("CEI57142-OBS-012","4.3.1.1.3","DPCC","PdC_Qi","1","VArRtg","setMag","R","plant","Maximum reactive power inductive"),
Rule("CEI57142-OBS-013","4.3.1.1.3","DPCC","PdC_Qc","1","VArRtg","setMag","R","plant","Maximum reactive power capacitive"),
Rule("CEI57142-OBS-014","4.3.1.1.3","DPCC","PdC_VA","1","VARtg","setMag","R","plant","Maximum apparent power"),
Rule("CEI57142-OBS-020","4.3.1.1.4","DECP","DisFR","1","Beh","stVal","R","state","Plant regulation availability"),
Rule("CEI57142-OBS-021","4.3.1.1.5","DGEN","DisFR","1","Beh","stVal","R","state","Generation macro-block availability","generation_present"),
Rule("CEI57142-OBS-022","4.3.1.1.6","DSTO","DisFR","1","Beh","stVal","R","state","Storage macro-block availability","storage_present"),
Rule("CEI57142-OBS-030","4.3.1.1.7","MMXU","PdC","1","TotW","mag","R","measurement","P at PCC",period_s=4),
Rule("CEI57142-OBS-031","4.3.1.1.7","MMXU","PdC","1","TotVAr","mag","R","measurement","Q at PCC",period_s=4),
Rule("CEI57142-OBS-032","4.3.1.1.7","MMXU","PdC","1","PPV","mag","R","measurement","Voltage at PCC",period_s=4),
Rule("CEI57142-OBS-033","4.3.1.1.7","MMXU","PdC","1","A","mag","O","measurement","Phase currents at PCC",period_s=4),
Rule("CEI57142-OBS-040","4.3.1.1.7","MMXU",None,"1","TotW","mag","R","measurement","Aggregate generation-source P","generation_source_present",4),
Rule("CEI57142-OBS-041","4.3.1.1.7","MMXU","St","1","TotW","mag","R","measurement","Storage P","storage_present",4),
Rule("CEI57142-OBS-042","4.3.1.1.7","MMXU","SGG",None,"TotW","mag","R","measurement","Single generation-group P","generation_group_present",4),
Rule("CEI57142-OBS-050","4.3.1.1.8","XCBR","IDG","1","Pos","stVal","R","state","General breaker position"),
Rule("CEI57142-OBS-060","4.3.1.1.9","DGEN","SSGG",None,"Health","stVal","R","state","Generation-group state","generation_group_present"),
Rule("CEI57142-OBS-061","4.3.1.1.9","DGEN","SSGG",None,"GnGrId","stVal","E","identification","Generation-group identifier","generation_group_present"),
]
