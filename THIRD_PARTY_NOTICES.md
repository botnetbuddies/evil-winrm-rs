# Third-party notices

The application is LGPL-3.0-or-later. Vendored crates retain their own licenses, included in their directories. The dependency versions are recorded in `Cargo.lock`.

## Evil-WinRM helpers

The PowerShell files in `assets/powershell/` come from [Evil-WinRM revision 64d8e0f962d239643c4efadacce9f716bd5cb775](https://github.com/Hackplayers/evil-winrm/blob/64d8e0f962d239643c4efadacce9f716bd5cb775/evil-winrm.rb), licensed LGPL-3.0-or-later. Original helper author attributions are preserved in the scripts where present. No Ruby source is executed.

The Donut helper calls the loader's public `Inject` method so the requested process ID is honored. Identifier and character-expression template expansion is implemented in Rust.

The compatibility baseline also used [evil-winrm-py revision bb5710eb268d6aa136117529f71a92ca821c0fda](https://github.com/adityatelange/evil-winrm-py/tree/bb5710eb268d6aa136117529f71a92ca821c0fda).

## Vendored crates

| Crate | Version | License | Local changes |
| --- | --- | --- | --- |
| `winrm-rs` | 1.2.2 | MIT OR Apache-2.0 | Authentication, ticket/cache selection, message sealing, proxies, TLS identities, PSRP transport and cancellation fixes |
| `psrp-rs` | 2.0.2 | MIT OR Apache-2.0 | Failed-pipeline output, terminal exceptions, host metadata/callbacks, CLIXML rendering and serialized output limits |
| `reqwest` | 0.13.5 | MIT OR Apache-2.0 | Origin TLS name selection independent of routing, including CONNECT and SOCKS; HTTPS proxy TLS retains its own name |
| `rustyline` | 17.0.2 | MIT | Cooperative signal handling, buffered input, editor shortcuts, selection, macros, paste and completion behavior |

The `vendor/gssapi-cache`, `vendor/sspi-credentials` and `vendor/kerberos-cache` adapters are MIT-licensed. They provide scoped GSSAPI caches, explicit Windows SSPI credentials and portable Kerberos ticket contexts without changing the process's default identity or credential cache.

The portable Kerberos adapter uses [rskrb5 0.2.0](https://github.com/clelange/rskrb5) (Apache-2.0) and RustCrypto primitives. Legacy RC4 wrapping follows RFC 4757 with its published corrections. Synthetic interoperability fixtures use invented credentials and keys.

The NTLM ciphertext fixture in `vendor/winrm-rs/tests/fixtures/ntlm-sealed-fault.json` was generated independently with pyspnego using an invented session key. Python is not required to run the application or Rust tests.

## OpenSSL

CredSSP and PKCS#12 support use OpenSSL. The Windows GNU build tested with static linking used OpenSSL 3.6.5 from the official MSYS2 `mingw-w64-x86_64-openssl` package, version `3.6.5-1` (Apache-2.0).

- [MSYS2 package source](https://packages.msys2.org/packages/mingw-w64-x86_64-openssl?repo=mingw64)
- Archive SHA-256: `389d1af21e99223d9e2cd32d4c073131b276da85be7636bd8d23571f6938864f`
- License: [licenses/OpenSSL-LICENSE.txt](licenses/OpenSSL-LICENSE.txt)

Keep the OpenSSL license with statically linked distributions. Builds omitting both `credssp` and `pkcs12` do not need OpenSSL.

Other Cargo dependencies retain the licenses listed in their package metadata.
