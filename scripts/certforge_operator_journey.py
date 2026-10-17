"""Offline private SDK-operator unit/security journey. Not whole-app or live QA.

Requires an owner-admitted Node-enabled image with the reviewed, lock-bound
dependencies already present. Never downloads dependencies, runs migrations,
opens a vault, executes the production operator or submits another run.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LOCKED = {"jose": "6.2.9", "js-yaml": "4.3.2", "argparse": "2.0.1"}
SCOPE = "private-sdk-operator-unit-security-contract"
COMMANDS = [
    ["--experimental-strip-types", "--test", "--test-reporter=tap", "src/lib/vault/sdk-operator.test.ts"],
    ["--test", "--test-reporter=tap", "scripts/sdk-operator-dependency.test.mjs"],
]


class NotReady(Exception):
    pass


def source_contract(root=ROOT):
    config = json.loads((root / "docs/sdk-operator-config.DISABLED.json").read_text(encoding="utf-8"))
    if (config.get("enabled") is not False or config.get("public_key_pem") != ""
            or config.get("principal", {}).get("capabilities") != []):
        raise NotReady("disabled_defaults_changed")
    public = (root / "src/lib/vault/types.ts").read_text(encoding="utf-8")
    forbidden = public.split("export const FORBIDDEN_TOOLS = [", 1)[1].split("] as const", 1)[0]
    if not all('"' + name + '"' in forbidden for name in ("sdk_action_review", "sdk_operator_execute")):
        raise NotReady("private_public_boundary_missing")
    raw_lock = (root / "package-lock.json").read_bytes()
    lock = json.loads(raw_lock)
    for package, version in LOCKED.items():
        entry = lock["packages"]["node_modules/" + package]
        if entry.get("version") != version or not str(entry.get("integrity", "")).startswith("sha512-"):
            raise NotReady("dependency_lock_changed")
        # Admitted offline image/bundle owns custody of bytes; this checks its
        # installed version against the committed lock, not bundle authenticity.
        installed = json.loads((root / "node_modules" / package / "package.json").read_text(encoding="utf-8"))
        if installed.get("version") != version:
            raise NotReady("offline_dependency_version_mismatch")
    return hashlib.sha256(raw_lock).hexdigest()


def node_supported(version):
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)\s*", version)
    return bool(match and tuple(map(int, match.groups())) >= (22, 12, 0))


def run(argv, timeout, *, env):
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True,
                            timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        # Never copy raw upstream exception bodies or process environment.
        raise NotReady("offline_command_failed")
    return result.stdout


def tap_passed(output, minimum):
    count = re.search(r"^# tests (\d+)\s*$", output, re.M)
    passed = re.search(r"^# pass (\d+)\s*$", output, re.M)
    failed = re.search(r"^# fail (\d+)\s*$", output, re.M)
    if (not count or not passed or not failed or int(count[1]) < minimum
            or int(passed[1]) != int(count[1]) or int(failed[1]) != 0):
        raise NotReady("test_evidence_incomplete")
    return int(passed[1])


def main():
    start = time.monotonic()
    try:
        node = shutil.which("node")
        if not node:
            raise NotReady("node_runtime_missing")
        # Tests use synthetic credentials only. Do not inherit service secrets.
        env = {k: v for k, v in os.environ.items()
               if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"}}
        env["NO_COLOR"] = "1"
        if not node_supported(run([node, "--version"], 5, env=env)):
            raise NotReady("node_22_12_or_newer_required")
        lock_sha = source_contract()
        run([node, "--input-type=module", "-e", "import 'jose'; import 'js-yaml'; import 'argparse';"], 5, env=env)
        evidence = []
        for args in COMMANDS:
            remaining = 60 - (time.monotonic() - start)
            if remaining <= 1:
                raise NotReady("journey_time_budget_exhausted")
            output = run([node, *args], min(20, remaining), env=env)
            minimum = 44 if args == COMMANDS[0] else 1
            passed = tap_passed(output, minimum)
            evidence.append({"suite": args[-1], "passed": passed,
                             "stdout_sha256": hashlib.sha256(output.encode()).hexdigest()})
        if source_contract() != lock_sha:
            raise NotReady("lock_or_boundary_contract_changed_during_journey")
        print("CERTFORGE_OPERATOR_JOURNEY_OK " + json.dumps({"scope": SCOPE, "suites": evidence,
              "package_lock_sha256": lock_sha, "live_acceptance": False, "installation_verified": False,
              "elapsed_s": round(time.monotonic() - start, 2)}, sort_keys=True))
        return 0
    except (NotReady, OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, NotReady) else "offline_prerequisite_or_execution_unavailable"
        print("CERTFORGE_OPERATOR_JOURNEY_NOT_READY " + json.dumps({"scope": SCOPE, "reason": reason,
              "live_acceptance": False, "installation_verified": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
