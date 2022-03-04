import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(eq=False)
class Interval():
    start: Optional[float] = None
    end: Optional[float] = None

    def duration(self) -> float:
        if self.start is None or self.end is None:
            raise ValueError(f"Interval not complete! [{self.start}, {self.end}]")

        return self.end - self.start


class Timer():
    """A helper for recording the times of a sequence of events.

    This object is not thread safe.
    """

    def __init__(self, timer: Callable[[], float] = time.time):
        self.times = {}
        self.timer = timer
        self.last_name: Optional[str] = None
        self.total = Interval()

    def mark(self, name: str = None) -> float:
        """Record a new event.

        If called without `name`, any previously started event will be marked
        as completed, but no new event will be started.
        """
        t = self.timer()
        if self.last_name is not None:
            self.times[self.last_name].end = t
        elif self.total.start is None:
            self.total.start = t

        if name is not None:
            self.times[name] = Interval(start=t)
        self.last_name = name
        self.total.end = t

        return t

    def log_all(self, logger: logging.Logger, level: int = logging.DEBUG):
        if not self.times or self.total.end is None:
            return

        for name, interval in self.times.items():
            logger.log(level, "ET for %s: %.4fs", name, interval.duration())

        logger.log(level, "ET for total: %.4fs", self.total.duration())
