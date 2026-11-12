# Free secret protection

This repository uses the free Gitleaks CLI, pinned to 8.30.1 with official
SHA-256 checksums. No Gitleaks Action licence, GitHub Secret Protection
subscription, API key or paid service is required.

## Install on each clone

Requirements: Git, Python 3.9 or newer, and internet access for the first scanner
download. Use Linux or macOS x64/arm64. On Windows, run the hooks inside WSL
with Git and Python installed there. The scanner also has native Windows
binaries, but native Windows hook chaining has not been validated.
Run from the repository root:

```bash
python3 .secret-guard/guard.py install
```

This installs local pre-commit and pre-push checks. Existing hooks (including
Husky) are chained, not deleted. Git does not install hooks when cloning, so each
contributor and automated coding checkout must run this command. Run it again
after moving the clone or after a package manager resets `core.hooksPath`.

## What runs

* Pre-commit scans staged changes and rejects private environment/credential paths.
* Pre-push scans every outgoing commit, including secrets added and later removed.
  New branches/tags conservatively scan their entire ancestry. Existing secrets
  in that history can block the first push; review them rather than bypassing it.
* GitHub Actions scans pushed/PR commit ranges. It has read-only permissions,
  an eight-minute limit, cancels superseded scans and has no recurring schedule.
* A manual Actions run scans the current tracked files. Select `full_history`
  for a separate historical audit. Large backup repositories can exceed the
  limit; run the audit locally in that case.
* Findings show only rule, filename and line number. Secret values, matched
  lines and raw scanner output are withheld. No finding artifacts are uploaded.

Only `.env.*.example`, `.env.*.sample`, `.env.*.template` (including the simple
`.env.example` forms) are allowed as environment templates. Their contents are
still scanned. Public certificates and non-secret `.npmrc` configuration are
allowed; private key material and embedded tokens are detected by content.
The dedicated Gitleaks configuration extends all default rules and adds Convex
deployment keys and private application-token assignments. It does not change
other scanners' configuration or accept inline `gitleaks:allow` bypasses.

## Run checks yourself

```bash
python3 .secret-guard/guard.py staged
python3 .secret-guard/guard.py snapshot
python3 .secret-guard/guard.py history
python3 .secret-guard/test_guard.py
```

The tests use synthetic values only. A failed download, missing history,
scanner error or timeout is a failed check, never a successful scan.

## Cost and limits

Local hooks cost no hosting minutes. Standard Linux GitHub Actions uses the
account's included allowance for private repositories and is free on public
repositories under GitHub's standard-runner policy. Keep the GitHub Actions
spending budget at $0 with **Stop usage** enabled. When the included allowance
runs out, hosted checks stop; local checks continue. This workflow does not
change billing or buy additional minutes.

Local hooks can be bypassed and do not cover GitHub web/API edits. Actions runs
after data reaches GitHub; it cannot prevent the initial exposure. On plans
supporting branch protection, require **Secret scan** before merging. No claim
of server-side push blocking is made by this setup. It does not revoke keys,
remove old Git history or certify that existing repository content is clean.
