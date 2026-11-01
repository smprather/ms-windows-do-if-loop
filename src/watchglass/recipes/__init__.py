"""Built-in recipes: hooks watchglass provides for `recipe = "<name>"` watches (see `watchglass docs recipes`).

Each module defines check(ctx) and on_true(ctx) and runs in the Python worker, so it uses only the
standard library and watchglass's stdlib-only modules. Its settings are validated by watchglass.config.
"""

from __future__ import annotations


class Failures:
    """What a queue runner keeps while it carries on: the first transient failure and the first rejection.

    A rejection (a `permanent_reason` from a rejected credential or host key) outranks any transient failure,
    whatever order the files happened to fail in (issue 28). Reporting the failure met first would let a timeout
    earlier in the queue hide a later rejection: the poll looked transient, the watch backed off, and the same
    wrong password was tried again (the behavior issue 24 removed).
    """

    __slots__ = ("transient", "rejection")

    def __init__(self) -> None:
        self.transient: Exception | None = None
        self.rejection: Exception | None = None

    def __bool__(self) -> bool:
        return self.rejection is not None or self.transient is not None

    def note(self, exc: Exception) -> None:
        """Remember `exc`: the first of each kind, so the report names what went wrong first."""
        if getattr(exc, "permanent_reason", None) is not None:
            if self.rejection is None:
                self.rejection = exc
        elif self.transient is None:
            self.transient = exc

    def raise_if_any(self) -> None:
        """Raise the rejection when there was one, else the first transient failure; nothing for a clean queue."""
        failure = self.rejection or self.transient
        if failure is not None:
            raise failure


def file_budget(remaining: float, files_left: int, limit: float) -> float:
    """Seconds one file may take: an equal share of what is left of the action, capped by `limit` when set.

    A share, not the whole budget, so one slow file cannot starve the rest of the queue; the last file gets
    whatever is left. `limit` is the recipe's `file_timeout` (0 or less: no extra cap).
    """
    share = remaining / max(files_left, 1)
    return share if limit <= 0 else min(share, limit)
