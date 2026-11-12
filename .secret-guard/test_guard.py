#!/usr/bin/env python3
"""Integration checks using synthetic credentials in disposable repositories."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent
SYNTHETIC = "ghp_" + hashlib.sha256(b"nonfunctional secret guard fixture").hexdigest()[:36]


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="secret-guard-test-")
        self.root = Path(self.temporary.name)
        shutil.copytree(SOURCE, self.root / ".secret-guard", ignore=shutil.ignore_patterns("__pycache__"))
        self.git("init", "-q")
        self.git("config", "user.name", "Secret Guard Test")
        self.git("config", "user.email", "secret-guard-test@example.invalid")
        self.write("README.md", "Synthetic test repository\n")
        self.git("add", ".")
        self.commit()
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args, **kwargs):
        return subprocess.run(["git", *args], cwd=self.root, text=True,
                              capture_output=True, check=True, **kwargs)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "Synthetic fixture")

    def guard(self, *args, data=None, env=None):
        return subprocess.run([sys.executable, ".secret-guard/guard.py", *args],
                              cwd=self.root, text=True, input=data,
                              capture_output=True, env=env, timeout=60)

    def assert_blocked(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(SYNTHETIC, result.stdout + result.stderr)

    def test_clean_staged_and_snapshot(self):
        self.assertEqual(self.guard("staged").returncode, 0)
        self.assertEqual(self.guard("snapshot").returncode, 0)

    def test_private_environment_filename(self):
        self.write("nested/.env.production", "SETTING=hello\n")
        self.git("add", ".")
        self.assert_blocked(self.guard("staged"))

    def test_template_allowed_but_secret_content_blocked(self):
        self.write(".env.local.example", "API_KEY=\n")
        self.git("add", ".")
        self.assertEqual(self.guard("staged").returncode, 0)
        self.write(".env.local.example", "API_KEY=" + SYNTHETIC + "\n")
        self.git("add", ".")
        self.assert_blocked(self.guard("staged"))

    def test_staged_bytes_win_over_clean_worktree(self):
        self.write("sample.py", 'TOKEN="' + SYNTHETIC + '"\n')
        self.git("add", ".")
        self.write("sample.py", "TOKEN=None\n")
        self.assert_blocked(self.guard("staged"))

    def test_untracked_secret_is_not_scanned(self):
        self.write(".env.local", "API_KEY=" + SYNTHETIC + "\n")
        self.assertEqual(self.guard("staged").returncode, 0)
        self.assertEqual(self.guard("snapshot").returncode, 0)

    def test_secret_added_then_deleted_still_blocks_range(self):
        self.write("sample.py", 'TOKEN="' + SYNTHETIC + '"\n')
        self.git("add", ".")
        self.commit()
        self.git("rm", "sample.py")
        self.commit()
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.assert_blocked(self.guard("range", self.base, head))

    def test_env_added_then_deleted_still_blocks_range(self):
        self.write(".env", "SETTING=hello\n")
        self.git("add", ".")
        self.commit()
        self.git("rm", ".env")
        self.commit()
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.assert_blocked(self.guard("range", self.base, head))

    def test_new_branch_and_deleted_branch(self):
        self.write("sample.py", 'TOKEN="' + SYNTHETIC + '"\n')
        self.git("add", ".")
        self.commit()
        head = self.git("rev-parse", "HEAD").stdout.strip()
        zeros = "0" * 40
        self.assert_blocked(self.guard("pre-push", data=f"refs/heads/test {head} refs/heads/test {zeros}\n"))
        self.assertEqual(self.guard("pre-push", data=f"(delete) {zeros} refs/heads/test {head}\n").returncode, 0)

    def test_missing_history_fails_closed(self):
        self.assert_blocked(self.guard("range", "1" * 40, self.base))

    def test_broken_scanner_fails_closed(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("guard", SOURCE / "guard.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original = module.scanner()
        cache = self.root / "broken-cache"
        binary = cache / "gnosis-secret-guard" / module.VERSION / original.parent.name / original.name
        binary.parent.mkdir(parents=True)
        binary.write_text("not executable")
        self.assert_blocked(self.guard("staged", env={**os.environ, "XDG_CACHE_HOME": str(cache)}))

    def test_installer_chains_existing_hooks_and_push_stdin(self):
        old = self.root / "old hooks"
        old.mkdir()
        pre_commit = old / "pre-commit"
        pre_commit.write_text("#!/bin/sh\nprintf original > hook-marker\n")
        pre_commit.chmod(0o755)
        pre_push = old / "pre-push"
        pre_push.write_text("#!/bin/sh\ncat > push-input\n")
        pre_push.chmod(0o755)
        self.git("config", "core.hooksPath", str(old))
        self.assertEqual(self.guard("install").returncode, 0)
        self.assertEqual(self.guard("install").returncode, 0)
        wrapper = Path(self.git("config", "core.hooksPath").stdout.strip())
        result = subprocess.run([str(wrapper / "pre-commit")], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "hook-marker").read_text(), "original")
        data = "(delete) " + "0" * 40 + " refs/heads/old " + self.base + "\n"
        result = subprocess.run([str(wrapper / "pre-push"), "origin", "unused"],
                                cwd=self.root, input=data, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "push-input").read_text(), data)

    def test_ci_push_uses_event_range(self):
        self.write("safe.txt", "safe\n")
        self.git("add", ".")
        self.commit()
        head = self.git("rev-parse", "HEAD").stdout.strip()
        event = self.root / "event.json"
        event.write_text(json.dumps({"before": self.base, "after": head, "deleted": False}))
        env = {**os.environ, "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event)}
        self.assertEqual(self.guard("ci", env=env).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
