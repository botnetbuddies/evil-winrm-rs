"""Opted-in Linux terminal checks; requires WINRM_HOST/USER/PASSWORD and a release build.
Set WINRM_TLS=1 for HTTPS. WINRM_TERMINAL_ARTIFACT_DIR preserves logs when set.
Set WINRM_BROKER_STATE to exercise the interactive broker adapter.
"""

from pathlib import Path
import errno
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import termios
import time
import uuid
import tempfile
import subprocess

# Development-only, Unix PTY acceptance test against an explicitly selected
# Windows lab. The Rust application has no Python runtime dependency.
binary = os.environ.get(
    "WINRM_BINARY",
    str(Path(__file__).resolve().parents[1] / "target/release/evil-winrm-rs"),
)
host = os.environ["WINRM_HOST"]
username = os.environ["WINRM_USER"]
password = os.environ["WINRM_PASSWORD"]


def redact(text):
    return text.replace(password, "[redacted]") if password else text


scratch = tempfile.TemporaryDirectory(prefix="ewr-terminal-")
terminal_dir = Path(
    os.environ.get("WINRM_TERMINAL_ARTIFACT_DIR", scratch.name)
).resolve()
terminal_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
reaped = False
transcript = terminal_dir / "session.log"
download = terminal_dir / "downloaded.txt"
scripts = terminal_dir / "scripts"
scripts.mkdir(exist_ok=True)
(scripts / "local a's script.ps1").write_text("Write-Output ('LOCAL'+'-SCRIPT-LOADED')")
(scripts / "module probe.psm1").write_text("function Test-EwrModuleProbe { 'MODULE'+'-LOADED' }; 'MODULE'+'-READY'")
(scripts / "data probe.psd1").write_text("@{Value='DATA-READY'}")
executables = terminal_dir / "executables"
executables.mkdir(exist_ok=True)
executable_prefix = "ewr-complete-" + uuid.uuid4().hex
cwd_executable = Path.cwd() / (executable_prefix + "-cwd.exe")
cwd_executable.write_bytes(b"")
(executables / (executable_prefix + "-configured.exe")).write_bytes(b"")

if download.exists():
    download.unlink()
if transcript.exists():
    transcript.unlink()
name = "ewr-terminal-" + uuid.uuid4().hex
prompt = r"\*evil-winrm-rs\* PS [^\r\n]*> "
pid, master = pty.fork()
if pid == 0:
    env = dict(
        os.environ, TERM="xterm-256color", XDG_DATA_HOME=str(terminal_dir / "data")
    )
    os.execve(
        binary,
        [
            binary,
            *(["--broker", "--daemon-state", os.environ["WINRM_BROKER_STATE"]]
              if os.environ.get("WINRM_BROKER_STATE") else []),
            "-i",
            host,
            "-u",
            username,
            "-p",
            password,
            *(["-S"] if os.environ.get("WINRM_TLS") == "1" else []),
            "--no-colors",
            "--log-file",
            str(transcript),
            "--scripts",
            str(scripts),
            "--executables", str(executables),
        ],
        env,
    )
fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 35, 160, 0, 0))
buffer = ""
seen = ""
results = []
ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def expect(pattern, timeout=30):
    global buffer, seen
    until = time.monotonic() + timeout
    while True:
        plain = ansi.sub("", buffer)
        match = re.search(pattern, plain)
        if match:
            buffer = plain[match.end() :]
            if pattern == prompt:
                time.sleep(0.1)
            return plain[: match.end()]
        if time.monotonic() > until:
            raise AssertionError(
                "terminal timeout waiting for "
                + pattern
                + "; tail: "
                + redact(plain[-1500:])
            )
        ready, _, _ = select.select(
            [master], [], [], min(0.25, until - time.monotonic())
        )
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    raise AssertionError(
                        "terminal process exited: " + redact(plain[-1500:])
                    )
                raise
            if not data:
                raise AssertionError("terminal EOF")
            text = data.decode("utf-8", errors="replace")
            buffer += text
            seen += text


def send(text):
    os.write(master, text.encode())


def marker(command, text):
    send(command + "\r")
    expect(r"(?m)^" + re.escape(text) + r"\r?$")
    expect(prompt)


def collect(seconds=0.8):
    global buffer, seen
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        ready, _, _ = select.select([master], [], [], max(0, until-time.monotonic()))
        if ready:
            text = os.read(master, 65536).decode("utf-8", errors="replace")
            if not text: break
            buffer += text
            seen += text
    text = ansi.sub("", buffer)
    buffer = ""
    return text


def completion(line):
    send(line + "\t\t")
    text = collect()
    send("\x03")
    expect(prompt)
    return text


try:
    expect(prompt)
    send("Clear-Host; Write-Host ('HELLO'+'-HOST'); Get-Date -Format yyyy; 'CLEAR'+'-DONE'\r")
    cleared = expect(prompt)
    assert "HELLO-HOST" in cleared and "CLEAR-DONE" in cleared
    assert "Error:" not in cleared and "Information:" not in cleared
    assert "\x1b[2J" in seen
    results.append("Clear-Host inside a compound command preserves host/date output: pass")
    send("Write-Output ('CTRL'+'-DELETE-OK') rubbish\x1b[1;5D\x1b[3;5~\r")
    expect(r"(?m)^CTRL-DELETE-OK\r?$")
    expect(prompt)
    assert "rubbish" not in transcript.read_text().split("PS> ")[-1]
    send("Write-Output ('ALT'+'-BACKSPACE-OK') rubbish\x1b\x7f\r")
    expect(r"(?m)^ALT-BACKSPACE-OK\r?$")
    expect(prompt)
    assert "rubbish" not in transcript.read_text().split("PS> ")[-1]
    results.append("Ctrl+Delete removes the next word; Alt+Backspace removes the previous word: pass")
    # Native editor features: exercise complete key sequences against a real PTY.
    send("Write-Output rubbish\x1b[1;6D('SELECT'+'-OK')\r")
    expect(r"(?m)^SELECT-OK\r?$")
    expect(prompt)
    send("Write-Output ('CUT'+'-YANK-OK')\x1b[1;2H\x17\x19\r")
    expect(r"(?m)^CUT-YANK-OK\r?$")
    expect(prompt)
    send("Write-Output ('COPY'+'-OK')\x1b[1;2H\x1bw\x05; \x19\r")
    expect(r"(?m)^COPY-OK\r?$")
    expect(r"(?m)^COPY-OK\r?$")
    expect(prompt)
    marker("Write-Output ('LAST'+'-ARGUMENT-OK')", "LAST-ARGUMENT-OK")
    send("Write-Output \x1b.\r")
    expect(r"(?m)^LAST-ARGUMENT-OK\r?$")
    expect(prompt)
    send("Write-Output ('MACRO'+'-\x18(x\x18)\x18e')\r")
    expect(r"(?m)^MACRO-xx\r?$")
    expect(prompt)
    send("Write-Output ('MACRO2'+'-\x18e')\r")
    expect(r"(?m)^MACRO2-x\r?$")
    expect(prompt)
    marker("Write-Output ('SEARCH'+'-FORWARD-OK')", "SEARCH-FORWARD-OK")
    send("\x13SEARCH\x1b[C\r")
    expect(r"(?m)^SEARCH-FORWARD-OK\r?$")
    expect(prompt)
    marker("Write-Output ('OPERATE'+'-ONE')", "OPERATE-ONE")
    marker("Write-Output ('OPERATE'+'-TWO')", "OPERATE-TWO")
    send("\x1b[A\x1b[A\x0f")
    expect(r"(?m)^OPERATE-ONE\r?$")
    expect(prompt)
    send("\r")
    expect(r"(?m)^OPERATE-TWO\r?$")
    expect(prompt)
    send("Write-Output 'LITERAL\x11\t-TAB'\r")
    expect(r"(?m)^LITERAL\t-TAB\r?$")
    expect(prompt)
    results.append("selection/copy/cut/yank, last argument, persistent macros, forward search, Ctrl+O and literal Ctrl+Q: pass")
    send("\x1b[200~Write-Output ('ATOMIC'+'-ONE')\r\nWrite-Output ('ATOMIC'+'-TWO')\rWrite-Output ('ATOMIC'+'-THREE')\x1b[201~")
    time.sleep(0.4)
    assert "ATOMIC-ONE" not in transcript.read_text(), "paste executed before Enter"
    send("\r")
    for word in ("ATOMIC-ONE", "ATOMIC-TWO", "ATOMIC-THREE"):
        expect(r"(?m)^" + word + r"\r?$")
    expect(prompt)
    results.append("atomic paste of complete commands with CRLF/CR normalization: pass")
    send("menu\r")
    initial_menu = expect(prompt)
    assert "upload <local> [remote]" in initial_menu
    assert "Functions added in this session" not in initial_menu
    assert len(initial_menu.splitlines()) < 45, "menu unexpectedly dumped remote functions"
    marker(
        "function Test-EwrTabProbe { 'completion-probe' }; 'function-created'",
        "function-created",
    )
    send("Test-EwrTabPro\t\r")
    expect(r"(?m)^completion-probe\r?$")
    expect(prompt)
    send("\x1b[A\r")
    expect(r"(?m)^completion-probe\r?$")
    expect(prompt)
    results += [
        "loaded function command completion: pass",
        "up-arrow history replay: pass",
    ]
    send("menu\r")
    loaded_menu = expect(prompt)
    assert "Functions added in this session" in loaded_menu
    assert "  Test-EwrTabProbe" in loaded_menu
    assert len(loaded_menu.splitlines()) < 50
    results.append("concise menu with command usage and session-added functions: pass")
    marker("function Test-EwrAllOne {'one'}; function Test-EwrAllTwo {'two'}; 'ALL'+'-READY'", "ALL-READY")
    send("Test-EwrAll\x1b*")
    completion_text = collect()
    send("\x03")
    expect(prompt)
    assert "Test-EwrAllOne Test-EwrAllTwo" in completion_text
    send("help\t\t")
    help_text = collect()
    send("\x07\x03")
    expect(prompt)
    assert "upload" in help_text and "Test-EwrAllOne" in help_text
    results.append("insert-all completion and help<Tab> discovery retain list-style completion: pass")
    setup = f"$global:ewrTerminalRoot=Join-Path $env:TEMP '{name}'; New-Item -ItemType Directory -Path $global:ewrTerminalRoot | Out-Null; Set-Location $global:ewrTerminalRoot; [IO.File]::WriteAllText((Join-Path $global:ewrTerminalRoot \"completion a's file.txt\"),'completion download'); 'files-created'"
    marker(setup, "files-created")
    send(".\\\t")
    expect(re.escape("completion a''s file.txt"))
    send("\x03")
    expect(prompt)
    results.append("first-word .\\ remote file completion with apostrophe/space quoting: pass")
    marker("[IO.File]::WriteAllText((Join-Path $pwd.Path 'log.ps1'),\"Write-Output ('PREFIX'+'-PRESERVED')\"); 'script-created'", "script-created")
    send(".\\lo\t\r")
    expect(r"(?m)^PREFIX-PRESERVED\r?$")
    expect(prompt)
    assert "PS> .\\log.ps1" in transcript.read_text()
    results.append("partial .\\lo path completion retains .\\ and executes the script: pass")
    marker("New-Item -ItemType Directory -Path 'filter-directory' | Out-Null; [IO.File]::WriteAllText((Join-Path $pwd.Path 'filter-file.txt'),'fixture'); 'FILTER'+'-READY'", "FILTER-READY")
    folders = completion("cd .\\filter-")
    assert "filter-directory" in folders and "filter-file.txt" not in folders
    for filename in ("filter.ps1", "filter.dll", "filter.exe", "filter.txt"):
        (terminal_dir / filename).write_text("Write-Output ('TILDE'+'-SCRIPT-OK')")
    for command_name, expected, excluded in (("loadps", "filter.ps1", ("filter.dll", "filter.exe")), ("loaddll", "filter.dll", ("filter.ps1", "filter.exe")), ("runexe", "filter.exe", ("filter.ps1", "filter.dll"))):
        choices = completion(command_name + " '" + str(terminal_dir) + "/filter")
        assert expected in choices and all(other not in choices for other in excluded)
    choices = completion("runexe " + executable_prefix)
    assert executable_prefix + "-cwd.exe" in choices and executable_prefix + "-configured.exe" in choices
    # A manually typed tilde is expanded by dispatch, independently of completion.
    with tempfile.TemporaryDirectory(prefix="ewr-tilde-", dir=Path.home()) as home_fixture:
        script_file = Path(home_fixture) / "tilde.ps1"
        script_file.write_text("Write-Output ('TILDE'+'-SCRIPT-OK')")
        marker("loadps '~/" + str(script_file.relative_to(Path.home())) + "'", "TILDE-SCRIPT-OK")
        choices = completion("loadps '~/" + str(script_file.parent.relative_to(Path.home())) + "/t")
        assert "~/" in choices and "tilde.ps1" in choices
    marker("'module probe.psm1'", "MODULE-READY")
    send("Test-EwrModulePro\t\r")
    expect(r"(?m)^MODULE-LOADED\r?$")
    expect(prompt)
    send("'data probe.psd1'\r")
    expect("DATA-READY")
    expect(prompt)
    # An independent shell changes the listing while the interactive cache remains live.
    assert "cached-new.txt" not in completion("download .\\cached-")
    script = "[IO.File]::WriteAllText((Join-Path (Join-Path $env:TEMP '" + name + "') 'cached-new.txt'),'fixture')"
    probe = subprocess.run([binary, "-i", host, "-u", username, "-p", password, *(["-S"] if os.environ.get("WINRM_TLS") == "1" else []), "--no-colors", "--command", script], capture_output=True, text=True, timeout=30)
    assert probe.returncode == 0, redact(probe.stderr)
    assert "cached-new.txt" not in completion("download .\\cached-")
    time.sleep(10.1)
    assert "cached-new.txt" in completion("download .\\cached-")
    results.append("directory/extension filters, merged search paths, tilde dispatch/display, module/data scripts and ten-second cache expiry: pass")
    send("local\t\r")
    expect(r"(?m)^LOCAL-SCRIPT-LOADED\r?$")
    expect(prompt)
    results.append("quoted local script-name completion and configured search directory: pass")
    send("Write-Output `\r")
    time.sleep(0.15)
    send(" ('TICK'+'-CONTINUED')\r")
    expect(r"(?m)^TICK-CONTINUED\r?$")
    expect(prompt)
    send("Write-Output 'pipe' |\r")
    time.sleep(0.15)
    send(" ForEach-Object { $_ + '-continued' }\r")
    expect(r"(?m)^pipe-continued\r?$")
    expect(prompt)
    send("\x1b[200~& {\r\n $value='BLOCK'\r\n Write-Output ($value+'-PASTED')\r\n}\x1b[201~\r")
    expect(r"(?m)^BLOCK-PASTED\r?$")
    expect(prompt)
    marker("Write-Output 'C:\\Windows\\'", "C:\\Windows\\")
    results.append("backtick continuation, newline pipeline, bracketed multiline paste and literal Windows backslashes: pass")
    send("download completion\t '" + str(download) + "'\r")
    until = time.monotonic() + 30
    while not download.exists() and time.monotonic() < until:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            chunk = os.read(master, 65536).decode("utf-8", errors="replace")
            buffer += chunk
            seen += chunk
    assert download.read_bytes() == b"completion download"
    expect(prompt)
    results.append("quoted apostrophe/space path completion and download: pass")
    upload_source = terminal_dir / "cancel-upload.bin"
    with upload_source.open("wb") as file:
        file.truncate(256 * 1024 * 1024)
    marker("[IO.File]::WriteAllText((Join-Path $pwd.Path 'cancel-target.bin'),'original destination'); 'cancel-fixture-ready'", "cancel-fixture-ready")
    send("upload '" + str(upload_source).replace("'", "''") + "' 'cancel-target.bin'\r")
    time.sleep(0.7)
    cancelled_at = time.monotonic()
    send("\x03")
    expect(prompt, 10)
    cancel_seconds = time.monotonic() - cancelled_at
    marker("if([IO.File]::ReadAllText((Join-Path $pwd.Path 'cancel-target.bin')) -ne 'original destination'){throw 'destination changed'}; if(@(Get-ChildItem -Filter 'cancel-target.bin.*.part').Count){throw 'staging file leaked'}; if(@(Get-Variable -Scope Global -Name 'ewrUpload*' | Where-Object { $_.Value -is [IO.Stream] }).Count){throw 'file handle leaked'}; 'upload-cancel-recovered'", "upload-cancel-recovered")
    upload_source.unlink()
    results.append(f"one Ctrl+C cancels upload in {cancel_seconds:.2f}s, preserves destination, cleans staging/handle and keeps session usable: pass")
    marker(
        "Write-Warning 'terminal warning'; Write-Output 'warning-finished'",
        "warning-finished",
    )
    assert "Warning: terminal warning" in transcript.read_text()
    send("Start-Sleep -Seconds 60\r")
    time.sleep(0.7)
    send("\x03")
    expect(prompt, 35)
    marker("'usable-after-cancel'", "usable-after-cancel")
    results.append("Ctrl+C during a pipeline and session recovery: pass")
    send("\x03")
    expect(prompt)
    send("\x0c")
    marker("'usable-after-clear'", "usable-after-clear")
    results += ["Ctrl+C while idle: pass", "Ctrl+L and continued input: pass"]
    marker(
        "Set-Location $env:TEMP; Remove-Item -LiteralPath $global:ewrTerminalRoot -Recurse -Force; 'terminal-cleanup-done'",
        "terminal-cleanup-done",
    )
    send("\x04")
    until = time.monotonic() + 20
    status = None
    while time.monotonic() < until:
        waited, value = os.waitpid(pid, os.WNOHANG)
        if waited:
            status = value
            reaped = True
            break
        time.sleep(0.1)
    assert status is not None and os.waitstatus_to_exitcode(status) == 0
    results.append("Ctrl+D clean exit: pass")
    text = transcript.read_text()
    for expected in [
        "PS> Test-EwrTabProbe",
        "Warning: terminal warning",
        "usable-after-cancel",
        "terminal-cleanup-done",
    ]:
        assert expected in text, expected
    assert "\x1b[31m" not in seen and "\x1b[33m" not in seen
    results.append("transcript and --no-colors: pass")
    (terminal_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("\n".join(results))
finally:
    cwd_executable.unlink(missing_ok=True)
    (terminal_dir / "terminal-capture.txt").write_text(redact(seen))
    if not reaped:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    os.close(master)
