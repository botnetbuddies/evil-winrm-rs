/* Development-only Windows ConPTY acceptance test. No credentials are embedded.
 * EWR_TEST_COMMAND supplies the full CLI invocation through the local environment.
 * API reference: https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session
 */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CAPACITY (2 * 1024 * 1024)
static char captured[CAPACITY];
static size_t captured_len;
static CRITICAL_SECTION capture_lock;
static HANDLE output_read;
static HANDLE input_write;
static HANDLE child_process;
static const char *stage = "initialization";

static DWORD WINAPI drain_output(LPVOID unused) {
    (void)unused;
    char bytes[4096];
    DWORD count;
    while (ReadFile(output_read, bytes, sizeof(bytes), &count, NULL) && count) {
        EnterCriticalSection(&capture_lock);
        if (captured_len + count < CAPACITY) {
            memcpy(captured + captured_len, bytes, count);
            captured_len += count;
            captured[captured_len] = 0;
        }
        LeaveCriticalSection(&capture_lock);
    }
    return 0;
}
static size_t mark(void) {
    EnterCriticalSection(&capture_lock);
    size_t offset = captured_len;
    LeaveCriticalSection(&capture_lock);
    return offset;
}
static int wait_text(size_t offset, const char *needle, DWORD timeout) {
    ULONGLONG deadline = GetTickCount64() + timeout;
    while (GetTickCount64() < deadline) {
        EnterCriticalSection(&capture_lock);
        int found = strstr(captured + offset, needle) != NULL;
        LeaveCriticalSection(&capture_lock);
        if (found) return 1;
        if (child_process && WaitForSingleObject(child_process, 0) == WAIT_OBJECT_0) return 0;
        Sleep(20);
    }
    return 0;
}
static int send_text(const char *text) {
    DWORD written;
    DWORD length = (DWORD)strlen(text);
    return WriteFile(input_write, text, length, &written, NULL) && written == length;
}
static int command(const char *text, const char *expected) {
    size_t offset = mark();
    if (!send_text(text) || !wait_text(offset, expected, 35000)) return 0;
    /* Allow the following prompt to finish before emitting the next keystroke. */
    Sleep(250);
    return 1;
}

int wmain(void) {
    HANDLE input_read = NULL, output_write = NULL, reader = NULL;
    HPCON console = NULL;
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION child;
    SIZE_T bytes = 0;
    DWORD exit_code = 1;
    wchar_t invocation[32768];
    wchar_t jea[2];
    int attributes_initialized = 0;
    int is_jea = GetEnvironmentVariableW(L"EWR_TEST_JEA", jea, 2) == 1 && jea[0] == L'1';
    int result = 1;
    memset(&startup, 0, sizeof(startup));
    memset(&child, 0, sizeof(child));
    InitializeCriticalSection(&capture_lock);
    DWORD invocation_length = GetEnvironmentVariableW(L"EWR_TEST_COMMAND", invocation, 32768);
    if (!invocation_length || invocation_length >= 32768) goto cleanup;
    if (!CreatePipe(&input_read, &input_write, NULL, 0) ||
        !CreatePipe(&output_read, &output_write, NULL, 0)) goto cleanup;
    if (FAILED(CreatePseudoConsole((COORD){160, 40}, input_read, output_write, 0, &console))) goto cleanup;
    startup.StartupInfo.cb = sizeof(startup);
    /* The host itself may have redirected output (e.g. under WinRM). Null
     * standard handles request the new console's handles rather than copies
     * of those redirected host handles. */
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!startup.lpAttributeList ||
        !InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) goto cleanup;
    attributes_initialized = 1;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console, sizeof(console), NULL, NULL)) goto cleanup;
    reader = CreateThread(NULL, 0, drain_output, NULL, 0, NULL);
    if (!reader || !CreateProcessW(NULL, invocation, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startup.StartupInfo, &child)) goto cleanup;
    child_process = child.hProcess;
    SecureZeroMemory(invocation, sizeof(invocation));
    CloseHandle(input_read); input_read = NULL;
    CloseHandle(output_write); output_write = NULL;
    stage = "initial prompt";
    if (!wait_text(0, "*evil-winrm-rs* PS ", 35000)) goto cleanup;
    Sleep(250);
    if (is_jea) {
        stage = "JEA static prompt";
        if (!wait_text(0, "*evil-winrm-rs* PS JEA>", 1000)) goto cleanup;
        stage = "JEA restricted menu";
        if (!command("menu\r", "(Disabled in JEA)")) goto cleanup;
        stage = "JEA hides disabled helper completions";
        size_t jea_completion_offset = mark();
        if (!send_text("uplo\t")) goto cleanup;
        if (wait_text(jea_completion_offset, "upload", 700)) goto cleanup;
        if (!send_text("\x03")) goto cleanup;
        Sleep(250);
        stage = "JEA scripting helper rejection";
        if (!command("upload missing.file\r", "unavailable in JEA mode")) goto cleanup;
        stage = "JEA hidden command rejection";
        if (!command("Get-Process\r", "Error:")) goto cleanup;
        stage = "JEA allowed command and recovery";
        SYSTEMTIME now;
        char year[8];
        GetSystemTime(&now);
        snprintf(year, sizeof(year), "%04u", now.wYear);
        if (!command("Get-Date -Format yyyy\r", year)) goto cleanup;
        goto clean_exit;
    }
    stage = "Clear-Host in a compound command";
    if (!command("Clear-Host; Write-Host ('NATIVE'+'-HOST-OK'); Get-Date -Format yyyy; 'HOST'+'-DONE'\r", "HOST-DONE")) goto cleanup;
    stage = "Ctrl+Delete next word";
    if (!command("Write-Output ('CTRL'+'-DELETE-OK') rubbish\x1b[1;5D\x1b[3;5~\r", "CTRL-DELETE-OK")) goto cleanup;
    stage = "Alt+Backspace previous word";
    /* ConPTY requests Win32 input mode (9001h): send VK_BACK with LEFT_ALT_PRESSED.
     * https://github.com/microsoft/terminal/blob/main/doc/specs/%234999%20-%20Improved%20keyboard%20handling%20in%20Conpty.md
     */
    if (!command("Write-Output ('ALT'+'-BACKSPACE-OK') rubbish\x1b[8;14;8;1;2;1_\x1b[8;14;8;0;2;1_\r", "ALT-BACKSPACE-OK")) goto cleanup;
    stage = "selected text replacement";
    if (!command("Write-Output rubbish\x1b[1;6D('NATIVE'+'-SELECT-OK')\r", "NATIVE-SELECT-OK")) goto cleanup;
    stage = "selection cut and yank";
    if (!command("Write-Output ('NATIVE'+'-CUT-OK')\x1b[1;2H\x17\x19\r", "NATIVE-CUT-OK")) goto cleanup;
    stage = "previous command last argument";
    if (!command("Write-Output \x1b[190;52;46;1;2;1_\x1b[190;52;46;0;2;1_\r", "NATIVE-CUT-OK")) goto cleanup;
    stage = "record and replay keyboard macro";
    if (!command("Write-Output ('NATIVE'+'-MACRO-\x18(x\x18)\x18" "e')\r", "NATIVE-MACRO-xx")) goto cleanup;
    stage = "keyboard macro persists across prompts";
    if (!command("Write-Output ('NATIVE'+'-MACRO2-\x18" "e')\r", "NATIVE-MACRO2-x")) goto cleanup;
    stage = "forward history search";
    if (!command("\x13MACRO2\x1b[C\r", "NATIVE-MACRO2-x")) goto cleanup;
    stage = "literal Ctrl+Q";
    if (!command("if ('A\x11\tB'.Contains([char]9)) {'NATIVE'+'-LITERAL-TAB-OK'} else {throw 'literal tab missing'}\r", "NATIVE-LITERAL-TAB-OK")) goto cleanup;
    stage = "Ctrl+O history continuation";
    if (!command("Write-Output ('NATIVE'+'-OPERATE-ONE')\r", "NATIVE-OPERATE-ONE")) goto cleanup;
    if (!command("Write-Output ('NATIVE'+'-OPERATE-TWO')\r", "NATIVE-OPERATE-TWO")) goto cleanup;
    if (!command("\x1b[A\x1b[A\x0f", "NATIVE-OPERATE-ONE")) goto cleanup;
    if (!command("\r", "NATIVE-OPERATE-TWO")) goto cleanup;
    stage = "persistent function setup";
    if (!command("$global:ewrConsoleCount=0; function Get-EwrConsoleProbe { $global:ewrConsoleCount++; ('console-probe:'+$global:ewrConsoleCount) }; 'NATIVE'+'-READY'\r", "NATIVE-READY")) goto cleanup;
    stage = "command completion";
    if (!command("Get-EwrConsolePro\t\r", "console-probe:1")) goto cleanup;
    stage = "history replay";
    if (!command("\x1b[A\r", "console-probe:2")) goto cleanup;
    stage = "concise menu and loaded functions";
    if (!command("menu\r", "Functions added in this session")) goto cleanup;
    stage = "remote script completion fixture";
    if (!command("$global:ewrConsoleOriginalLocation=$pwd.Path; $global:ewrConsoleDirectory=Join-Path $env:TEMP ('ewr-console-'+[guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $global:ewrConsoleDirectory | Out-Null; Set-Location $global:ewrConsoleDirectory; [IO.File]::WriteAllText((Join-Path $pwd.Path \"completion a's file.ps1\"),\"Write-Output ('NATIVE'+'-PATH-OK')\"); 'FILES'+'-READY'\r", "FILES-READY")) goto cleanup;
    stage = "first-word remote path completion and quoted invocation";
    if (!command(".\\\t\r", "NATIVE-PATH-OK")) goto cleanup;
    stage = "partial relative-path completion fixture";
    if (!command("[IO.File]::WriteAllText((Join-Path $pwd.Path 'log.ps1'),\"Write-Output ('NATIVE'+'-PREFIX-OK')\"); 'PREFIX'+'-READY'\r", "PREFIX-READY")) goto cleanup;
    stage = "partial path completion preserves dot-backslash";
    if (!command(".\\lo\t\r", "NATIVE-PREFIX-OK")) goto cleanup;
    stage = "backtick continuation";
    if (!send_text("Write-Output `\r")) goto cleanup;
    Sleep(500);
    if (!command(" ('NATIVE'+'-TICK-OK')\r", "NATIVE-TICK-OK")) goto cleanup;
    stage = "pipeline continuation";
    if (!send_text("Write-Output 'NATIVE' |\r")) goto cleanup;
    Sleep(500);
    if (!command(" ForEach-Object { $_ + '-PIPE-OK' }\r", "NATIVE-PIPE-OK")) goto cleanup;
    stage = "bracketed multiline paste";
    if (!command("\x1b[200~& {\r\n $value='NATIVE'\r\n Write-Output ($value+'-PASTE-OK')\r\n}\x1b[201~\r", "NATIVE-PASTE-OK")) goto cleanup;
    stage = "atomic complete-command paste";
    size_t paste_offset = mark();
    if (!send_text("\x1b[200~Write-Output ('NATIVE'+'-ATOMIC-ONE')\r\nWrite-Output ('NATIVE'+'-ATOMIC-TWO')\rWrite-Output ('NATIVE'+'-ATOMIC-THREE')\x1b[201~")) goto cleanup;
    if (wait_text(paste_offset, "NATIVE-ATOMIC-ONE", 700)) goto cleanup;
    if (!command("\r", "NATIVE-ATOMIC-THREE")) goto cleanup;
    stage = "paste newline normalization";
    if (!command("\x1b[200~if ('A\r\nB'.Length -eq 3 -and 'C\rD'.Length -eq 3) { 'NATIVE'+'-NEWLINES-OK' } else { throw 'newlines not normalized' }\x1b[201~\r", "NATIVE-NEWLINES-OK")) goto cleanup;
    char upload_file[32768];
    DWORD upload_length = GetEnvironmentVariableA("EWR_TEST_UPLOAD_FILE", upload_file, sizeof(upload_file));
    if (upload_length && upload_length < sizeof(upload_file)) {
        stage = "upload cancellation fixture";
        if (!command("[IO.File]::WriteAllText((Join-Path $pwd.Path 'cancel-target.bin'),'original destination'); 'UPLOAD'+'-READY'\r", "UPLOAD-READY")) goto cleanup;
        char upload_command[33000];
        /* Fixture paths must not contain a PowerShell single quote. */
        if (strchr(upload_file, '\'')) goto cleanup;
        snprintf(upload_command, sizeof(upload_command), "upload '%s' 'cancel-target.bin'\r", upload_file);
        stage = "one Ctrl+C cancels upload";
        if (!send_text(upload_command)) goto cleanup;
        Sleep(700);
        size_t offset = mark();
        ULONGLONG start = GetTickCount64();
        if (!send_text("\x03") || !wait_text(offset, "*evil-winrm-rs* PS ", 10000)) goto cleanup;
        printf("One Ctrl+C returned the upload prompt in %llu ms.\n", (unsigned long long)(GetTickCount64()-start));
        Sleep(250);
        stage = "upload cancellation cleanup and session reuse";
        if (!command("if([IO.File]::ReadAllText((Join-Path $pwd.Path 'cancel-target.bin')) -ne 'original destination'){throw 'destination changed'}; if(@(Get-ChildItem -Filter 'cancel-target.bin.*.part').Count){throw 'staging leaked'}; if(@(Get-Variable -Scope Global -Name 'ewrUpload*' | Where-Object { $_.Value -is [IO.Stream] }).Count){throw 'handle leaked'}; 'UPLOAD'+'-RECOVERED'\r", "UPLOAD-RECOVERED")) goto cleanup;
    }
    stage = "file fixture cleanup";
    if (!command("Set-Location $global:ewrConsoleOriginalLocation; Remove-Item -LiteralPath $global:ewrConsoleDirectory -Recurse -Force; 'FILES'+'-REMOVED'\r", "FILES-REMOVED")) goto cleanup;
    stage = "static method setup";
    if (!command("Add-Type 'public static class EwrConsoleMethod { public static string Echo() { return \"NATIVE-STATIC\"; } }'; $global:showmethods='[EwrConsoleMethod]::Echo()'; 'METHOD'+'-READY'\r", "METHOD-READY")) goto cleanup;
    stage = "static method completion";
    if (!command("[EwrConsoleMeth\t\r", "NATIVE-STATIC")) goto cleanup;
    stage = "Ctrl+C during a command";
    if (!send_text("Start-Sleep -Seconds 60\r")) goto cleanup;
    Sleep(1000);
    if (!send_text("\x03")) goto cleanup;
    Sleep(1000);
    if (!command("'AFTER'+'-CANCEL'\r", "AFTER-CANCEL")) goto cleanup;
    stage = "Ctrl+C while idle";
    if (!send_text("\x03")) goto cleanup;
    Sleep(500);
    if (!command("'AFTER'+'-IDLE'\r", "AFTER-IDLE")) goto cleanup;
    stage = "clear and continued input";
    if (!send_text("\x0c") || !command("'AFTER'+'-CLEAR'\r", "AFTER-CLEAR")) goto cleanup;
clean_exit:
    stage = "Ctrl+D exit";
    if (!send_text("\x04") || WaitForSingleObject(child.hProcess, 20000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(child.hProcess, &exit_code) || exit_code != 0) goto cleanup;
    result = 0;
cleanup:
    if (result) fprintf(stderr, "Windows terminal validation failed at %s (Win32 %lu)\n", stage, (unsigned long)GetLastError());
    if (child.hProcess && WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) {
        TerminateProcess(child.hProcess, 1);
        WaitForSingleObject(child.hProcess, 5000);
    }
    if (console) ClosePseudoConsole(console);
    if (reader) {
        if (WaitForSingleObject(reader, 5000) != WAIT_OBJECT_0) {
            CancelSynchronousIo(reader);
            WaitForSingleObject(reader, INFINITE);
        }
        CloseHandle(reader);
    }
    wchar_t path[32768];
    if (GetEnvironmentVariableW(L"EWR_TEST_CAPTURE", path, 32768)) {
        FILE *file = _wfopen(path, L"wb");
        if (file) { fwrite(captured, 1, captured_len, file); fclose(file); }
    }
    if (startup.lpAttributeList) {
        if (attributes_initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    }
    if (child.hThread) CloseHandle(child.hThread);
    if (child.hProcess) CloseHandle(child.hProcess);
    if (input_read) CloseHandle(input_read);
    if (input_write) CloseHandle(input_write);
    if (output_read) CloseHandle(output_read);
    if (output_write) CloseHandle(output_write);
    DeleteCriticalSection(&capture_lock);
    if (!result) puts(is_jea
        ? "Windows ConPTY JEA: static prompt, restricted menu, helper/hidden-command rejection, recovery and Ctrl+D pass."
        : "Windows ConPTY: Clear-Host, word deletion, selection/cut/yank, last argument, macros, forward search, Ctrl+O/Q, concise menu, command/file/static-method completion, backtick/pipeline continuation, atomic multiline paste/newline normalization, history, Ctrl+C running/idle, clear, Ctrl+D and session recovery pass.");
    return result;
}
