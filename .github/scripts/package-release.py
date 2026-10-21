"""Package a tagged executable, its license notices and platform instructions."""

import argparse
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=("x86_64-unknown-linux-gnu", "x86_64-pc-windows-gnu"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    version = tomllib.loads((args.source / "Cargo.toml").read_text())["package"]["version"]
    tag = os.environ.get("RELEASE_TAG") or f"v{version}"
    if tag != f"v{version}":
        parser.error(f"tag {tag!r} does not match Cargo version {version!r}")
    commit = subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip()
    timestamp = int(subprocess.check_output(["git", "-C", str(args.source), "log", "-1", "--format=%ct"], text=True))
    windows = args.target.endswith("windows-gnu")
    platform = "windows-x86_64" if windows else "linux-x86_64"
    name = f"evil-winrm-rs-{tag}-{platform}"
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ewr-package-") as temporary:
        package = Path(temporary) / name
        package.mkdir()
        binary = package / ("evil-winrm-rs.exe" if windows else "evil-winrm-rs")
        shutil.copyfile(args.binary, binary)
        binary.chmod(0o755)
        for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(args.source / filename, package / filename)
        shutil.copytree(args.source / "licenses", package / "licenses")
        for license in (args.source / "vendor").glob("*/LICENSE*"):
            if license.is_file():
                destination = package / license.relative_to(args.source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(license, destination)
        runtime = (
            "Windows x64. OpenSSL is linked statically; no OpenSSL installation is needed.\n"
            if windows else
            "Linux x64, glibc 2.39+, OpenSSL 3 and MIT Kerberos/GSSAPI runtime libraries.\n"
        )
        command = ".\\evil-winrm-rs.exe" if windows else "./evil-winrm-rs"
        (package / "README.txt").write_text(
            f"evil-winrm-rs {tag}\n\n{runtime}"
            "All Cargo features are enabled. No Rust compiler, Ruby or Python runtime is needed.\n\n"
            f"{command} --help\n{command} -i windows.example.test -u user\n\n"
            "Documentation: https://github.com/botnetbuddies/evil-winrm-rs/wiki\n"
            f"Source: https://github.com/botnetbuddies/evil-winrm-rs/tree/{commit}\n"
            f"Target: {args.target}\n", encoding="utf-8"
        )
        if windows:
            archive = args.output / f"{name}.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
                for path in sorted(package.rglob("*")):
                    if path.is_file():
                        output.write(path, path.relative_to(package.parent))
        else:
            archive = args.output / f"{name}.tar.gz"
            with archive.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=timestamp) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as output:
                    def metadata(info):
                        info.uid = info.gid = 0
                        info.uname = info.gname = "root"
                        info.mtime = timestamp
                        return info
                    output.add(package, arcname=name, filter=metadata)
        print(archive)


if __name__ == "__main__":
    main()
