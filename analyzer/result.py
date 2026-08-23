from dataclasses import dataclass
@dataclass
class Issue:
    severity:str; rule_id:str; ied:str; location:str; description:str
    def as_tuple(self): return self.severity,self.rule_id,self.ied,self.location,self.description
