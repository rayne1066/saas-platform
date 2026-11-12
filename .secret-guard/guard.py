#!/usr/bin/env python3
"""Free local/CI secret checks. Never print file contents or scanner output."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

VERSION = "8.30.1"
CHECKSUMS = {
    "darwin_arm64": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    "darwin_x64": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    "linux_arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    "linux_x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "windows_arm64": "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",
    "windows_x64": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
}
HOOKS = ("applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
         "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
         "pre-rebase", "post-checkout", "post-merge", "pre-push", "post-rewrite",
         "pre-auto-gc", "sendemail-validate", "post-index-change")
HERE = Path(__file__).resolve().parent


def fail(message):
    raise RuntimeError(message)


def git(*args, optional=False):
    result = subprocess.run(["git", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode and not optional:
        fail("Git could not complete a safety check. Fetch missing history and retry.")
    return result.stdout


def scanner():
    system = platform.system().lower()
    arch = {"aarch64": "arm64", "arm64": "arm64", "amd64": "x64",
            "x86_64": "x64"}.get(platform.machine().lower())
    target = f"{system}_{arch}"
    if target not in CHECKSUMS:
        fail("Unsupported scanner platform. Use a supported Linux, macOS or Windows x64/arm64 machine.")
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    cache = cache / "gnosis-secret-guard" / VERSION / target
    binary = cache / ("gitleaks.exe" if system == "windows" else "gitleaks")
    if binary.is_file():
        return binary
    extension = "zip" if system == "windows" else "tar.gz"
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{target}.{extension}"
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != CHECKSUMS[target]:
        fail("Scanner download checksum mismatch; refusing to execute it.")
    if extension == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            executable = archive.read("gitleaks.exe")
    else:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            executable = archive.extractfile("gitleaks").read()
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as handle:
        handle.write(executable)
        temporary = Path(handle.name)
    temporary.chmod(0o755)
    temporary.replace(binary)
    return binary


def scan(*args):
    # Capture both streams, then emit only selected metadata. No raw findings,
    # matched lines, secret values, commit messages or reports enter CI logs.
    command = [str(scanner()), *args, "--config", str(HERE / "gitleaks.toml"),
               "--redact=100", "--no-banner", "--no-color", "--exit-code=10",
               "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(HERE / "no-ignores"),
               "--report-format=json", "--report-path=-", "--timeout=180"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=200)
    if result.returncode == 10:
        try:
            findings = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            findings = []
        print("Secret guard blocked suspected credentials (values withheld):", file=sys.stderr)
        for item in findings[:30]:
            print(json.dumps({key: item.get(key) for key in ("RuleID", "File", "StartLine")}), file=sys.stderr)
        fail("Remove real credentials from the commit. Review false positives locally; do not paste keys into logs or chat.")
    if result.returncode:
        fail("Gitleaks could not finish. No scan result is being treated as a pass.")


def check_paths(raw):
    blocked = []
    for path in raw.decode("utf-8", "surrogateescape").split("\0"):
        if not path:
            continue
        name = PurePosixPath(path).name.lower()
        template = name.startswith(".env.") and name.rsplit(".", 1)[-1] in {"example", "sample", "template"}
        if ((name == ".env" or name.startswith(".env.")) and not template
                or name in {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credentials.json",
                            "service-account-key.json", "service-account-credentials.json"}
                or name.endswith((".p12", ".pfx", ".jks", ".keystore"))):
            blocked.append(path)
    if blocked:
        for path in sorted(set(blocked))[:30]:
            print("Blocked credential path: " + json.dumps(path), file=sys.stderr)
        fail("Keep private environment/credential files outside Git. Templates must contain placeholders only.")


def staged():
    check_paths(git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))
    scan("git", "--pre-commit", "--staged")


def commit_id(value):
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        fail("Invalid commit ID in scan request.")
    return git("rev-parse", "--verify", value + "^{commit}").decode().strip()


def revision_scan(revisions):
    if git("rev-parse", "--is-shallow-repository").strip() == b"true":
        fail("A complete history is required for commit-range scans. Run git fetch --unshallow first.")
    # Check every newly reachable commit, including an env file added then deleted.
    commits = git("rev-list", *revisions).decode().splitlines()
    if not commits:
        return
    for commit in commits:
        check_paths(git("diff-tree", "--root", "-m", "--no-commit-id", "--no-renames",
                        "-r", "--name-only", "--diff-filter=ACMR", "-z", commit))
    scan("git", "--log-opts=" + " ".join(revisions + ["--full-history", "-m"]))


def pre_push(data):
    for line in data.decode().splitlines():
        fields = line.split()
        if len(fields) != 4:
            fail("Malformed pre-push input.")
        _, local_sha, _, remote_sha = fields
        if set(local_sha) == {"0"}:  # Deleting a ref introduces no data.
            continue
        local_sha = commit_id(local_sha)
        if set(remote_sha) == {"0"}:
            # Conservatively scan all ancestry on a new branch/tag. This also
            # catches old secrets on first publication to another remote.
            revision_scan([local_sha])
        else:
            revision_scan([commit_id(remote_sha) + ".." + local_sha])


def snapshot():
    # Scan tracked bytes from the Git index, never untracked private .env files.
    check_paths(git("ls-files", "-z"))
    with tempfile.TemporaryDirectory(prefix="secret-guard-") as temporary:
        git("checkout-index", "--all", "--ignore-skip-worktree-bits",
            "--prefix=" + Path(temporary).as_posix() + "/")
        scan("dir", temporary)


def ci():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    name = os.environ["GITHUB_EVENT_NAME"]
    if name == "pull_request":
        base = commit_id(event["pull_request"]["base"]["sha"])
        head = commit_id(event["pull_request"]["head"]["sha"])
        revision_scan([base + ".." + head])
    elif name == "push" and not event.get("deleted"):
        head = commit_id(event["after"])
        before = event["before"]
        revision_scan([head] if set(before) == {"0"} else [commit_id(before) + ".." + head])
    elif name == "workflow_dispatch":
        if event.get("inputs", {}).get("full_history") in (True, "true"):
            revision_scan(["--all"])
        else:
            snapshot()
    else:
        fail("Unsupported CI event.")


def install():
    scanner()  # Never install a hook that cannot run its scanner.
    root = Path(git("rev-parse", "--show-toplevel").decode().strip())
    common = Path(git("rev-parse", "--git-common-dir").decode().strip()).resolve()
    wrappers = common / "secret-guard-hooks"
    current = git("config", "--get", "core.hooksPath", optional=True).decode().strip()
    if current != str(wrappers):
        previous = Path(os.path.expanduser(current)) if current else common / "hooks"
        if not previous.is_absolute():
            previous = root / previous
        git("config", "--local", "secretguard.previousHooksPath", str(previous))
    wrappers.mkdir(parents=True, exist_ok=True)
    for name in HOOKS:
        hook = wrappers / name
        hook.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
                        + shlex.quote(str(HERE / "guard.py")) + " hook " + name + ' "$@"\n')
        hook.chmod(0o755)
    git("config", "--local", "core.hooksPath", str(wrappers))
    print("Installed secret checks before commit and push; existing hooks are chained.")


def hook(name, args):
    data = sys.stdin.buffer.read() if name in {"pre-push", "post-rewrite"} else None
    if name == "pre-commit":
        staged()
    elif name == "pre-push":
        pre_push(data)
    previous = git("config", "--get", "secretguard.previousHooksPath", optional=True).decode().strip()
    if previous:
        original = Path(previous) / name
        if original.is_file() and os.access(original, os.X_OK):
            result = subprocess.run([str(original), *args], input=data)
            if result.returncode:
                raise SystemExit(result.returncode)


def main():
    os.chdir(git("rev-parse", "--show-toplevel").decode().strip())
    command = sys.argv[1] if len(sys.argv) > 1 else "staged"
    if command == "install":
        install()
    elif command == "staged":
        staged()
    elif command == "pre-push":
        pre_push(sys.stdin.buffer.read())
    elif command == "range" and len(sys.argv) == 4:
        revision_scan([commit_id(sys.argv[2]) + ".." + commit_id(sys.argv[3])])
    elif command == "snapshot":
        snapshot()
    elif command == "history":
        revision_scan(["--all"])
    elif command == "ci":
        ci()
    elif command == "hook" and len(sys.argv) >= 3:
        hook(sys.argv[2], sys.argv[3:])
    else:
        fail("Usage: python3 .secret-guard/guard.py install|staged|pre-push|range BASE HEAD|snapshot|history|ci")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print("Secret guard: " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Exceptions can contain external output or URLs; keep them out of logs.
        print("Secret guard could not finish; operation blocked. Check Git, Python 3 and network access.", file=sys.stderr)
        sys.exit(1)
