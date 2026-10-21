"""Finite, read-only packaged interpreter probe; no workload or child admission.

Invoked only by package-smoke.ps1 on the approved hosted Windows runner, with
the frozen bundled interpreter -I (deliberately without -B). Never run in Cloud.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys


def require(value, message):
    if not value:
        raise RuntimeError(message)


require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "HOSTED_WINDOWS_ONLY")
require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "HOSTED_RUNNER_ONLY")
require(os.environ.get("GITHUB_REPOSITORY") == "sterlingstreamsllc/windows-stability-guardrail-validation", "REPOSITORY_REQUIRED")
require(len(sys.argv) == 2, "FIXED_ROOT_ARGUMENT_REQUIRED")
root = Path(sys.argv[1])
require(root.is_absolute() and root.name == "PC-Stability-Guard-0.1.2-pkg.1", "PACKAGE_ROOT_REQUIRED")
require(sys.version_info[:3] == (3, 13, 16), "PINNED_RUNTIME_REQUIRED")
require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1, "ISOLATION_REQUIRED")
require(sys.flags.dont_write_bytecode == 0, "CACHE_FALLBACK_MUST_BE_EXERCISED")
require(struct.calcsize("P") == 8, "AMD64_RUNTIME_REQUIRED")
require(Path(sys.executable).resolve() == (root / "runtime/python.exe").resolve(), "ABSOLUTE_BUNDLED_RUNTIME_REQUIRED")
runtime = (root / "runtime").resolve()
initial_path = list(sys.path)
require(all(Path(p).resolve() in (runtime, runtime / "python313.zip") for p in initial_path), "UNEXPECTED_IMPORT_PATH")
require("sitecustomize" not in sys.modules and "usercustomize" not in sys.modules, "CUSTOMIZATION_REFUSED")
sentinel = root / "app/__pycache__"
info = sentinel.lstat()
require(stat.S_ISREG(info.st_mode) and info.st_size == 0 and not
        (info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT), "CACHE_SENTINEL_REQUIRED")
sys.path.insert(0, str(root / "app"))  # Same explicit insertion as unchanged guard.
import native as N
import pe_fixture

modules = {}
for module in (N, pe_fixture):
    source = root / "app" / (module.__name__ + ".py")
    require(Path(module.__file__).resolve() == source.resolve(), "FROZEN_SOURCE_IMPORT_REQUIRED")
    modules[module.__name__] = {"path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
m = N.MemoryStatus()
m.Length = ctypes.sizeof(m)
N.check(N.GlobalMemory(ctypes.byref(m)), "GlobalMemoryStatusEx")
memory = N.system_memory()
require(sentinel.is_file() and sentinel.stat().st_size == 0, "SENTINEL_CHANGED")
print(json.dumps({"status": "PROBE_COMPLETE", "python": sys.version,
    "executable": sys.executable, "isolated": True, "pointer_bits": 64,
    "initial_sys_path": initial_path, "imports": modules,
    "cache_write_requested": True, "cache_sentinel_bytes": 0,
    "physical_total_bytes": m.TotalPhys, "physical_available_bytes": m.AvailPhys,
    "commit_headroom_bytes": memory["commit_headroom"],
    "workload_admissions": 0, "child_processes_started": 0}))
