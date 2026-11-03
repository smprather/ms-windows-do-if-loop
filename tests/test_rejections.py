"""A rejected credential or host key is permanent: the shapes ssh/scp print, and the transient ones beside them."""

import pytest

from watchglass import transfer
from watchglass.ctx import CommandFailed
from watchglass.rejections import rejection_reason
from watchglass.transfer import TransferAuthFailed, TransferFailed


@pytest.mark.parametrize(
    "stderr",
    [
        "u@host: Permission denied (publickey,password).\n",
        "Permission denied (publickey,password,keyboard-interactive).\n",
        "Permission denied (publickey).\n",  # BatchMode: no password to offer
        "Received disconnect from 10.0.0.1 port 22:2: Too many authentication failures\n",
        "Too many authentication failures\n",
        "No more authentication methods to try.\n",
        "No supported authentication methods available (server sent: publickey,password)\n",
    ],
)
def test_authentication_rejections_are_permanent(stderr):
    assert rejection_reason(stderr) == "authentication failed"


@pytest.mark.parametrize(
    "stderr",
    [
        "Host key verification failed.\n",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n",
        "Host key for 10.0.0.1 has changed and you have requested strict checking.\n",
    ],
)
def test_host_key_rejections_are_permanent(stderr):
    assert rejection_reason(stderr) == "host key verification failed"


@pytest.mark.parametrize(
    "stderr",
    [
        "/in/a.bin: Permission denied\n",  # the classic protocol: a file, not the login
        'dest open "/in/a.bin": Permission denied\n',  # its sftp mode
        "scp: /remote/a.bin: Permission denied\n",
        "ssh: connect to host h port 22: Connection refused\n",
        "ssh: connect to host h port 22: Connection timed out\n",
        "Connection reset by peer\n",
        "banner exchange: Connection to 10.0.0.1 port 22: invalid format\n",
        "",
    ],
)
def test_transient_and_file_level_failures_are_retried(stderr):
    assert rejection_reason(stderr) is None


def test_a_failed_command_carries_the_classification():
    permanent = CommandFailed(["ssh"], 255, "u@host: Permission denied (publickey,password).\n")
    assert permanent.permanent_reason == "authentication failed"
    transient = CommandFailed(["ssh"], 255, "ssh: connect to host h port 22: Connection refused\n")
    assert transient.permanent_reason is None


@pytest.mark.parametrize(
    "console, reason",
    [
        (
            "u@h's password: \nu@h: Permission denied (publickey,password).\n"
            "C:\\Program Files\\OpenSSH\\scp.EXE: Connection closed\n",
            "authentication failed",
        ),
        ("\x1b[1t\x1b[cHost key verification failed.\n", "host key verification failed"),
    ],
)
def test_a_pty_rejection_on_stdout_is_permanent(console, reason):
    """conpty merges scp's stderr into stdout, so that is where its rejection appears (issue 29)."""
    exc = transfer._failed_command(["scp"], 255, "", console)
    assert isinstance(exc, TransferAuthFailed)
    assert exc.permanent_reason == reason
    assert exc.stderr == console  # the only error text there is, so it goes in the message
    assert console.strip().splitlines()[-1] in str(exc)


def test_a_pty_transient_failure_on_stdout_stays_transient():
    exc = transfer._failed_command(["scp"], 255, "", "ssh: connect to host h port 22: Connection timed out\n")
    assert isinstance(exc, CommandFailed)
    assert not isinstance(exc, TransferAuthFailed)
    assert exc.permanent_reason is None


def test_stderr_still_wins_when_a_non_pty_run_has_both():
    """Only a run whose stderr is empty (the pty) is classified from stdout: the normal path is unchanged."""
    exc = transfer._failed_command(
        ["scp"], 255, "ssh: connect to host h port 22: Connection refused\n", "Permission denied (publickey).\n"
    )
    assert isinstance(exc, CommandFailed)
    assert not isinstance(exc, TransferAuthFailed)
    assert exc.stderr.startswith("ssh: connect")


def test_a_transfer_rejection_is_a_transfer_failure_not_a_plain_command_failure():
    exc = TransferAuthFailed(["scp"], 255, "u@host: Permission denied (publickey).\n", "authentication failed")
    assert isinstance(exc, TransferFailed)
    assert not isinstance(exc, CommandFailed)
    assert exc.permanent_reason == "authentication failed"
    assert "Permission denied" in str(exc)
    assert exc.stderr.endswith("Permission denied (publickey).\n")
