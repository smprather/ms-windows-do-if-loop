"""Real Windows integration: a Task Scheduler task and a ConPTY, not the fakes the unit tests use.

Opt in with `WATCHGLASS_WINDOWS_INTEGRATION=1` on a Windows host (CI sets it): the tests register a scheduled
task and spawn a console process. The regular suite skips them, so a developer's own task and Startup folder
are never touched by an ordinary test run.
"""

from __future__ import annotations

import os
import sys

import pytest

from watchglass import conpty, winsched

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="needs Windows"),
    pytest.mark.skipif(
        os.environ.get("WATCHGLASS_WINDOWS_INTEGRATION") != "1",
        reason="set WATCHGLASS_WINDOWS_INTEGRATION=1 to run the real Task Scheduler/ConPTY tests",
    ),
]


@pytest.fixture
def scheduled_task(monkeypatch, tmp_path):
    """A throwaway task name and shortcut path: never touch the real watchglass task or Startup folder."""
    name = f"watchglass-ci-{os.getpid()}"
    shortcut = tmp_path / "watchglass.lnk"
    monkeypatch.setattr(winsched, "TASK_NAME", name)
    monkeypatch.setattr(winsched, "_SHORTCUT", f"'{shortcut}'")
    yield name
    winsched.run_powershell(winsched.unregister_script())  # best effort: the test removes it too


def test_the_task_probe_sees_a_registered_task_and_its_removal(scheduled_task):
    """Issue 32's fallback decision rests on this probe, so prove it against the real scheduler."""
    created = winsched.run_powershell(winsched.register_script("cmd.exe", "/c exit 0"))
    assert created.returncode == 0, created.stderr or created.stdout
    assert winsched.run_powershell(winsched.task_state_script()).stdout.strip() == "present"

    removed = winsched.run_powershell(winsched.unregister_script())
    assert removed.returncode == 0, removed.stderr or removed.stdout
    assert winsched.run_powershell(winsched.task_state_script()).stdout.strip() == "absent"


def test_conpty_types_the_password_and_scrubs_it(tmp_path):
    """Issues 29-30 came from the real pty merging stderr into stdout; prove it types and scrubs on Windows."""
    prompt = tmp_path / "prompt.py"
    prompt.write_text(
        "import sys\n"
        "print('Password: ', end='', flush=True)\n"
        "print('read', sys.stdin.readline().strip())\n",
        encoding="utf-8",
    )
    exit_code, output, stderr, timed_out = conpty.run([sys.executable, str(prompt)], "s3cret", limit=60)
    assert not timed_out
    assert exit_code == 0, output
    assert stderr == ""
    assert "read ***" in output
    assert "s3cret" not in output
