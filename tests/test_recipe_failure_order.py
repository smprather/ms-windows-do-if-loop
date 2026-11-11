"""Issue 28: a rejection must outrank a transient failure earlier in the same queue.

The queue-running recipes (push, pull, mirror both ways) keep going after a file fails and report at the end.
They reported the failure they met first, so a timeout earlier in the queue hid a later rejected credential:
the poll looked transient, the watch backed off, and the same wrong password was tried again (the behavior
issue 24 removed).
"""

import logging
import time

import pytest

from watchglass.ctx import CommandFailed, Ctx
from watchglass.recipes import mirror, pull, push
from watchglass.transfer import TransferAuthFailed, TransferFailed

SSH_OPTIONS = ("-F", "/dev/null", "-o", "IdentityAgent=none")


def rejection() -> TransferAuthFailed:
    return TransferAuthFailed(["scp"], 255, "u@host: Permission denied (publickey).\n", "authentication failed")


class FakeTransfer:
    """Answers each transfer call with the next outcome: an exception raises, anything else is returned."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def _next(self, where: str):
        self.calls.append(where)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def push(self, path, remote_dir, **options):
        return self._next(str(path))

    def pull(self, remote, local_dir, **options):
        self._next(str(remote))
        final = local_dir / str(remote).rsplit(":", 1)[-1].rsplit("/", 1)[-1]
        final.parent.mkdir(parents=True, exist_ok=True)
        final.write_bytes(b"payload")
        return final


class FakeCtx(Ctx):
    """A real Ctx (ledger, checkpoint, file_key, remaining) with its transfer replaced by a recorder."""

    def __init__(self, tmp_path, settings, *outcomes, payload=None):
        super().__init__(
            watch="w", hook="on_true", poll_id="p", condition=True, payload=payload, settings=settings,
            watch_dir=tmp_path, data_dir=tmp_path / "data", run_dir=tmp_path / "run",
            deadline=time.time() + 3600,
        )
        self._transfer = FakeTransfer(*outcomes)
        self.headlines = []
        self._emit = self.headlines.append
        self.log = logging.getLogger("watchglass.test.failure-order")

    @property
    def transfer(self):
        return self._transfer


def transfer_settings(settings, **overrides):
    base = {
        "protocol": "scp", "password_env": None, "password_mode": "askpass", "port": None,
        "identity": None, "known_hosts": None, "ssh_options": SSH_OPTIONS, "file_timeout": 0.0,
    }
    base.update(settings)
    base.update(overrides)
    return base


def push_settings(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    for name in ("a.bin", "b.bin"):
        (stage / name).write_bytes(b"payload")
    return transfer_settings({
        "dest": "u@host:/in", "local_dir": str(stage), "settle": 0.0, "pattern": "*", "ignore": [],
        "after": "delete", "archive_dir": str(tmp_path / "archive"), "keep_for": 0.0,
        "marker": "sha256", "resume": False, "reachable_host": None, "reachable_port": None,
        "reachable_timeout": 5.0, "reachable_probe": "tcp",
    })


def pull_settings(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    return transfer_settings({
        "remote": "u@host", "remote_dir": "/in", "local_dir": str(stage), "delete_remote": False,
        "checksum": False, "resume": False, "on_conflict": "rename", "on_missing": "skip",
        "part_max_age": 0.0,
    })


def mirror_settings(tmp_path, *, direction):
    tree = tmp_path / "tree"
    tree.mkdir()
    for name in ("a.bin", "b.bin"):
        (tree / name).write_bytes(b"payload")
    return transfer_settings({
        "direction": direction, "remote": "u@host", "remote_dir": "/tree", "local_dir": str(tree),
        "delete": False, "ignore": [], "mtime_tolerance": 2.0, "settle": 0.0, "resume": False,
        "part_max_age": 0.0, "remote_python": "auto", "ssh_command": None,
        "reachable_host": None, "reachable_port": None, "reachable_timeout": 5.0,
    })


def pull_payload():
    return [
        {"path": "/in/a.bin", "name": "a.bin", "size": 7, "sha256": None, "key": "a"},
        {"path": "/in/b.bin", "name": "b.bin", "size": 7, "sha256": None, "key": "b"},
    ]


def test_push_reports_a_rejection_after_a_transient_failure(tmp_path):
    settings = push_settings(tmp_path)
    files = [f"{settings['local_dir']}/{name}" for name in ("a.bin", "b.bin")]
    timeout = CommandFailed(["scp"], 255, "Connection timed out during banner exchange\n")
    ctx = FakeCtx(tmp_path, settings, timeout, rejection(), payload=files)
    with pytest.raises(TransferAuthFailed) as caught:
        push.on_true(ctx)
    assert caught.value.permanent_reason == "authentication failed"
    assert len(ctx.transfer.calls) == 2  # the rejection still stopped the queue


def test_pull_reports_a_rejection_after_a_transient_failure(tmp_path):
    ctx = FakeCtx(tmp_path, pull_settings(tmp_path), TransferFailed("timed out"), rejection(),
                  payload=pull_payload())
    with pytest.raises(TransferAuthFailed) as caught:
        pull.on_true(ctx)
    assert caught.value.permanent_reason == "authentication failed"
    assert len(ctx.transfer.calls) == 2


def test_mirror_push_reports_a_rejection_after_a_transient_failure(tmp_path):
    ctx = FakeCtx(tmp_path, mirror_settings(tmp_path, direction="push"),
                  TransferFailed("timed out"), rejection(),
                  payload={"copy": ["a.bin", "b.bin"]})
    with pytest.raises(TransferAuthFailed) as caught:
        mirror.on_true(ctx)
    assert caught.value.permanent_reason == "authentication failed"
    assert len(ctx.transfer.calls) == 2


def test_mirror_push_reports_a_rejection_from_the_remote_helper_after_a_transient_failure(tmp_path):
    denied = CommandFailed(["ssh"], 255, "u@host: Permission denied (publickey).\n")
    ctx = FakeCtx(tmp_path, mirror_settings(tmp_path, direction="push"),
                  TransferFailed("timed out"), denied,
                  payload={"copy": ["a.bin", "b.bin"]})
    with pytest.raises(CommandFailed) as caught:
        mirror.on_true(ctx)
    assert caught.value.permanent_reason == "authentication failed"
    assert len(ctx.transfer.calls) == 2  # the rejection still stopped the queue


def test_mirror_pull_reports_a_rejection_after_a_transient_failure(tmp_path):
    ctx = FakeCtx(tmp_path, mirror_settings(tmp_path, direction="pull"),
                  TransferFailed("timed out"), rejection(),
                  payload={"copy": ["a.bin", "b.bin"], "times": {}})
    with pytest.raises(TransferAuthFailed) as caught:
        mirror.on_true(ctx)
    assert caught.value.permanent_reason == "authentication failed"
    assert len(ctx.transfer.calls) == 2
