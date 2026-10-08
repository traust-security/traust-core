from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.detection_quality import RulePack
from traust_core.v1.models.operations import JobResult
from traust_core.v1.repositories.detection_quality import DetectionQualityUnitOfWork


class DetectionQualityService:
    def __init__(self, uow: DetectionQualityUnitOfWork) -> None:
        self._uow = uow

    def score(self, run_id: UUID) -> JobResult:
        raise NotImplementedError("stub: replaces match_benchmark.py, sweep/benchmark.py")

    def mine_rules(self) -> list[RulePack]:
        raise NotImplementedError("stub: replaces emit_rule_drafts.py, sweep/mining.py")

    def calibrate(self, rule_pack_id: UUID) -> JobResult:
        raise NotImplementedError("stub: replaces calibrate_rule_pack.py, sweep/calibration.py")

    def admit(self, rule_pack_id: UUID) -> JobResult:
        raise NotImplementedError("stub: replaces sweep/rule_lane.py admission")

    def misses(self) -> JobResult:
        raise NotImplementedError("stub: replaces cve_replay_monitor.py, build_critical_misses.py")
