"""Plant context used to evaluate conditional CEI 0-16 observability rules."""
from dataclasses import dataclass, field


@dataclass
class GenerationGroup:
    inst: str
    power_kw: float | None = None
    technology: str | None = None


@dataclass
class PlantContext:
    total_power_kw: float | None = None
    generation_present: bool = False
    storage_present: bool = False
    storage_ac: bool = False
    sources: set[str] = field(default_factory=set)
    generation_groups: list[GenerationGroup] = field(default_factory=list)
    auxiliary_only_consumption: bool = False

    @property
    def generation_group_required(self):
        # The exact V5 applicability depends on plant and unit data. Until the
        # required context is available, do not manufacture an ERROR.
        if self.total_power_kw is None:
            return False
        return self.total_power_kw >= 1000 and bool(self.generation_groups)

    def source_required(self, source):
        if source not in self.sources:
            return False
        # The V5 exception for certain 100 kW <= source < 500 kW plants is
        # conditional on information not inferable from a generic SCL model.
        return True

    def condition_applies(self, condition):
        return {
            "generation_present": self.generation_present,
            "storage_present": self.storage_present,
            "storage_ac_present": self.storage_present and self.storage_ac,
            "generation_group_required": self.generation_group_required,
            "generation_group_measurement_required": self.generation_group_required,
            "pv_aggregate_required": self.source_required("PV"),
            "wind_aggregate_required": self.source_required("WIND"),
            "thermal_aggregate_required": self.source_required("THERMAL"),
            "hydro_aggregate_required": self.source_required("HYDRO"),
        }.get(condition, False)
