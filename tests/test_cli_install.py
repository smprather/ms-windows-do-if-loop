import subprocess as _subprocess
import sys

import pytest
from click.testing import CliRunner

from watchglass import cli as cli_module
from watchglass import systemd, winsched
from watchglass.cli import cli


def run(*args):
    return CliRunner().invoke(cli, list(args))


def fake_systemctl(tmp_path, monkeypatch, exit_code=0):
    calls = tmp_path / "calls.txt"
    script = tmp_path / "systemctl"
    script.write_text(f'#!/bin/sh\necho "$@" >> "{calls}"\necho "fake failure" >&2\nexit {exit_code}\n'
                      if exit_code else f'#!/bin/sh\necho "$@" >> "{calls}"\n')
    script.chmod(0o755)
    monkeypatch.setenv("WATCHGLASS_SYSTEMCTL", str(script))
    return calls


def unit_file(xdg):
    return xdg.config_home.parent / "systemd" / "user" / "watchglass.service"


@pytest.mark.posix_only
def test_install_writes_the_unit_and_enables_it(xdg, tmp_path, monkeypatch):
    calls = fake_systemctl(tmp_path, monkeypatch)
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    result = run("install")
    assert result.exit_code == 0, result.output
    text = unit_file(xdg).read_text()
    assert "ExecStart=" in text and " run" in text
    assert 'Environment="PATH=' in text and "WantedBy=default.target" in text
    assert calls.read_text().splitlines() == ["--user daemon-reload", "--user enable --now watchglass.service"]
    assert "systemctl --user status watchglass" in result.output
    assert "SSH_AUTH_SOCK" not in result.output


@pytest.mark.posix_only
def test_install_warns_about_ssh_agent(xdg, tmp_path, monkeypatch):
    fake_systemctl(tmp_path, monkeypatch)
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ssh-XXXX/agent.123")
    result = run("install")
    assert result.exit_code == 0
    assert "SSH_AUTH_SOCK" in result.output and "watchglass docs environment" in result.output


@pytest.mark.posix_only
def test_install_dry_run_changes_nothing(xdg, tmp_path, monkeypatch):
    calls = fake_systemctl(tmp_path, monkeypatch)
    result = run("install", "--dry-run")
    assert result.exit_code == 0
    assert "[Service]" in result.output and "systemctl --user enable --now watchglass.service" in result.output
    assert not unit_file(xdg).exists() and not calls.exists()


@pytest.mark.posix_only
def test_install_reports_systemctl_failure(xdg, tmp_path, monkeypatch):
    fake_systemctl(tmp_path, monkeypatch, exit_code=1)
    result = run("install")
    assert result.exit_code == 1
    assert "fake failure" in result.output


@pytest.mark.posix_only
def test_uninstall(xdg, tmp_path, monkeypatch):
    calls = fake_systemctl(tmp_path, monkeypatch)
    assert run("install").exit_code == 0
    result = run("uninstall")
    assert result.exit_code == 0, result.output
    assert not unit_file(xdg).exists()
    assert calls.read_text().splitlines()[-2:] == ["--user disable --now watchglass.service", "--user daemon-reload"]


@pytest.mark.posix_only
def test_install_keeps_a_custom_config(xdg, tmp_path, monkeypatch):
    fake_systemctl(tmp_path, monkeypatch)
    custom = tmp_path / "custom.toml"
    custom.write_text("")
    assert run("--config", str(custom), "install").exit_code == 0
    assert f'--config "{custom.resolve()}" run' in unit_file(xdg).read_text()
    assert run("install").exit_code == 0
    assert "--config" not in unit_file(xdg).read_text()


@pytest.mark.posix_only
def test_find_executable_prefers_the_running_script(tmp_path, monkeypatch):
    script = tmp_path / "bin" / "watchglass"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "argv", [str(script), "install"])
    assert systemd.find_executable() == str(script)


def on_windows(monkeypatch, exit_codes=(), task_present=None, stderr="refused by policy"):
    """A fake PowerShell: script-aware for the task-state probe, exit codes in order for everything else.

    `task_present` answers the probe: None/False -> `absent` (the fallback path), True -> `present`, and
    "unknown" -> an unreadable answer (the probe itself failed).
    """
    scripts = []
    codes = list(exit_codes)

    def fake_powershell(script):
        scripts.append(script)
        if "Get-ScheduledTask" in script:
            if task_present == "unknown":
                return _subprocess.CompletedProcess(["powershell.exe"], 1, "", "")
            answer = "present\n" if task_present else "absent\n"
            return _subprocess.CompletedProcess(["powershell.exe"], 0, answer, "")
        code = codes.pop(0) if codes else 0
        return _subprocess.CompletedProcess(["powershell.exe"], code, "", stderr if code else "")

    monkeypatch.setattr(cli_module, "_on_windows", lambda: True)
    monkeypatch.setattr(winsched, "run_powershell", fake_powershell)
    return scripts


def test_windows_install_registers_and_starts_a_logon_task(xdg, monkeypatch):
    scripts = on_windows(monkeypatch)
    result = run("install")
    assert result.exit_code == 0, result.output
    register, start = scripts
    assert "Register-ScheduledTask" in register and "New-ScheduledTaskTrigger -AtLogOn" in register
    assert "-m watchglass run" in register and "watchglass.lnk" in register
    assert "Start-ScheduledTask" not in register and "Start-ScheduledTask" in start
    assert "registered Task Scheduler task 'watchglass'" in result.output and "started it" in result.output


def test_windows_install_start_failure_is_only_a_warning(xdg, monkeypatch):
    scripts = on_windows(monkeypatch, exit_codes=(0, 1))
    result = run("install")
    assert result.exit_code == 0, result.output
    assert len(scripts) == 2
    assert "will start at the next logon" in result.output


def test_windows_install_falls_back_to_a_startup_shortcut(xdg, monkeypatch):
    scripts = on_windows(monkeypatch, exit_codes=(1, 0))
    result = run("install")
    assert result.exit_code == 0, result.output
    assert any("Get-ScheduledTask" in script for script in scripts)  # it checked before falling back (issue 32)
    assert any("CreateShortcut" in script for script in scripts)
    assert "Startup-folder shortcut" in result.output


def test_windows_install_keeps_a_task_that_registered_despite_an_error(xdg, monkeypatch):
    """Issue 32: registration reported a problem, but the task exists: keep it, never add a second autostart entry."""
    scripts = on_windows(monkeypatch, exit_codes=(1, 0, 0), task_present=True)
    result = run("install")
    assert result.exit_code == 0, result.output
    assert not any("CreateShortcut" in script for script in scripts)
    assert any("Get-ScheduledTask" in script for script in scripts)
    assert any("Remove-Item" in script and "watchglass.lnk" in script for script in scripts)  # one mechanism only
    assert any("Start-ScheduledTask" in script for script in scripts)
    assert "refused by policy" in result.output  # the underlying error is surfaced, not "(no details)"
    assert "is registered" in result.output and "started it" in result.output


def test_the_shell_reason_prefers_stderr_and_falls_back_to_the_exit_code():
    """stdout can be incidental; the error message is what PowerShell put on stderr (issue 32)."""
    result = _subprocess.CompletedProcess(["powershell.exe"], 1, "some output\n", "Access is denied\n")
    assert cli_module._shell_reason(result) == "Access is denied"
    assert cli_module._shell_reason(
        _subprocess.CompletedProcess(["powershell.exe"], 1, "only stdout\n", "")
    ) == "only stdout"
    assert cli_module._shell_reason(
        _subprocess.CompletedProcess(["powershell.exe"], 1, "", "")
    ) == "exit code 1"


def test_the_task_state_probe_asks_task_scheduler_and_answers_both_ways():
    script = winsched.task_state_script()
    assert "Get-ScheduledTask" in script and "'present'" in script and "'absent'" in script


def test_windows_install_refuses_a_shortcut_when_the_task_state_is_unknown(xdg, monkeypatch):
    """If the task cannot be seen either way, a shortcut could duplicate it: fail instead of guessing (issue 32)."""
    scripts = on_windows(monkeypatch, exit_codes=(1,), task_present="unknown")
    result = run("install")
    assert result.exit_code == 1
    assert not any("CreateShortcut" in script for script in scripts)
    assert "could not be checked" in result.output


def test_windows_install_surfaces_the_exit_code_when_powershell_says_nothing(xdg, monkeypatch):
    """`(no details)` hid the cause; the exit code is the least the user needs to tell the failures apart."""
    on_windows(monkeypatch, exit_codes=(1, 0), stderr="")
    result = run("install")
    assert result.exit_code == 0, result.output
    assert "Task Scheduler refused (exit code 1)" in result.output
    assert "no details" not in result.output


def test_windows_install_fails_when_both_methods_fail(xdg, monkeypatch):
    on_windows(monkeypatch, exit_codes=(1, 1))
    result = run("install")
    assert result.exit_code == 1
    assert "refused by policy" in result.output


def test_windows_install_dry_run_and_custom_config(xdg, tmp_path, monkeypatch):
    scripts = on_windows(monkeypatch)
    custom = tmp_path / "custom.toml"
    custom.write_text("")
    result = run("--config", str(custom), "install", "--dry-run")
    assert result.exit_code == 0
    assert scripts == []
    assert "Register-ScheduledTask" in result.output and "CreateShortcut" in result.output
    assert "and no task exists" in result.output  # the fallback is conditional now (issue 32)
    assert f'--config "{custom.resolve()}" run' in result.output


def test_windows_uninstall(xdg, monkeypatch):
    scripts = on_windows(monkeypatch)
    result = run("uninstall")
    assert result.exit_code == 0, result.output
    (script,) = scripts
    assert "Unregister-ScheduledTask" in script and "watchglass.lnk" in script


def test_windows_uninstall_has_one_windows_branch():
    import inspect

    callback = cli_module.uninstall.callback
    assert callback is not None
    source = inspect.getsource(callback)
    assert source.count("if _on_windows():") == 1


@pytest.mark.posix_only
def test_the_unit_escapes_what_systemd_would_expand():
    """A `"` ends the quoted value, `%` is a specifier and `$` expands: a path can hold all three."""
    text = systemd.unit_text('/opt/keep "watch" 100%/$HOME/watchglass', '/usr/bin:/opt/$HOME/a%b')
    exec_line = next(line for line in text.splitlines() if line.startswith("ExecStart="))
    env_line = next(line for line in text.splitlines() if line.startswith('Environment="PATH='))
    assert '\\"watch\\"' in exec_line  # the quote does not end the value
    assert "100%%" in exec_line  # % is a specifier
    assert "$$HOME" in exec_line  # $ would be expanded by systemd
    assert "%%b" in env_line and "$HOME" in env_line and "$$" not in env_line  # no $ expansion there


@pytest.mark.posix_only
def test_uninstall_removes_the_unit_even_when_systemctl_cannot_run(xdg, tmp_path, monkeypatch):
    """An uninstall that cannot reach systemctl must still remove the unit file it installed."""
    unit_file(xdg).parent.mkdir(parents=True)
    unit_file(xdg).write_text("[Service]\n")
    monkeypatch.setenv("WATCHGLASS_SYSTEMCTL", str(tmp_path / "no-such-systemctl"))
    result = run("uninstall")
    assert not unit_file(xdg).exists()
    assert "cannot run systemctl" in result.output
