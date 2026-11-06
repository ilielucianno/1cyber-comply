"""Internal collector: checks that compliance is tracked continuously (NIS2 Art. 21(2)(f))."""
from app import config, scoring
from app.collectors.base import FAIL, PASS, BaseCollector, CheckResult


class ComplyCollector(BaseCollector):
    name = "comply"

    def __init__(self, framework_id: str = "nis2"):
        self.framework_id = framework_id

    def is_configured(self) -> bool:
        return True

    def test_connection(self) -> tuple[bool, str]:
        return True, "internal"

    def collect(self) -> list[CheckResult]:
        interval = config.COLLECT_INTERVAL_HOURS
        age = scoring.last_snapshot_age_hours(self.framework_id)
        points = len(scoring.history(self.framework_id))
        raw = {"interval_hours": interval, "snapshots": points,
               "last_snapshot_age_hours": None if age is None else round(age, 1)}
        if interval <= 0:
            return [CheckResult("score_history", FAIL,
                                "Automatic collection is disabled (COLLECT_INTERVAL_HOURS=0).", raw)]
        if age is None:
            return [CheckResult("score_history", FAIL, "No compliance score has been recorded yet.", raw)]
        if age > 2 * interval:
            return [CheckResult("score_history", FAIL,
                                f"Last compliance score is {age:.0f}h old; automatic collection every "
                                f"{interval:g}h appears to have stopped.", raw)]
        return [CheckResult("score_history", PASS,
                            f"Compliance is measured automatically every {interval:g}h "
                            f"({points} score snapshots recorded).", raw)]
