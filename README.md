<p align="center">
  <img src="logo.png" alt="evil-winrm-rs" width="360">
</p>

# evil-winrm-rs

A native Rust WinRM shell for Linux and Windows. Persistent PowerShell sessions, file transfers, script and assembly helpers, tab completion and multiline input—without a Ruby or Python runtime.

Also includes resumable/compressed transfers, proxy support, JSON output and remote exit codes, a session broker shared by CLI and MCP clients, and SOCKS5 forwarding through Windows.

**[Download](https://github.com/botnetbuddies/evil-winrm-rs/releases/latest)** · [Documentation](https://github.com/botnetbuddies/evil-winrm-rs/wiki) · [Authentication](https://github.com/botnetbuddies/evil-winrm-rs/wiki/Connections-and-authentication)

## Quick start

```sh
# The password prompt is hidden.
evil-winrm-rs -i windows.example.test -u 'DOMAIN\user'

# HTTPS
evil-winrm-rs -i windows.example.test -u 'DOMAIN\user' --ssl

evil-winrm-rs --help
```

Inside the shell, run `menu` for helpers. Tab completes commands and paths; Ctrl+C stops the current command or transfer.

## Install

Download the Linux or Windows x64 archive from [releases](https://github.com/botnetbuddies/evil-winrm-rs/releases/latest), extract it, and put the executable on your `PATH`. All features are included; Windows packages use static OpenSSL.

Linux packages need glibc 2.39+, OpenSSL 3 and Kerberos/GSSAPI runtime libraries. See [build and install](https://github.com/botnetbuddies/evil-winrm-rs/wiki/Build-and-install) for source builds, feature selection and Docker.

## Credits and license

Based on [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) and [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py).

[LGPL-3.0-or-later](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md) for dependencies and helper attributions.
