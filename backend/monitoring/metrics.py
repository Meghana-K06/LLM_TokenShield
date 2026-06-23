from collections import defaultdict
import time

class MetricsTracker:
    def __init__(self):
        self._counters = defaultdict(int)
        self._start_time = time.time()

    def increment(self, key: str):
        self._counters[key] += 1

    def get_all(self) -> dict:
        return {
            "uptime_seconds": round(time.time() - self._start_time, 2),
            **dict(self._counters)
        }
