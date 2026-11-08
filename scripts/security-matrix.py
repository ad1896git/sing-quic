#!/usr/bin/env python3
"""Run the SEC-MATRIX with bounded commands and inspectable per-row evidence."""

import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import shlex
import shutil
import subprocess
import sys
import time


NEKORAY = "1127938594e4c67352124ff6362dc704bd0faeeb"
QUIC = "7101329b86a0c801e643fc8ccf730ec89be10663"
SING_QUIC = "9c9fdac85d4bfbfa0336ea1c1154b384c84c259d"
PATCH = "libs/patches/quic-go-v0.47.0-beta.2-congestion-lock.patch"
PATCH_SHA256 = "ae512f0b0e7cf8c346f223f34ebd8846fa848b281fb50b5b7ce7b488fb29cf4c"
PROTOCOLS = ["hysteria", "hysteria2", "tuic"]


MODULE = "github.com/sagernet/sing-quic"
PARENT = "TestLowDatagramRoundTrip"
SIGNATURE = "PROTOCOL_VIOLATION (local): DATAGRAM frame too large"
KNOWN_SKIP = ("KNOWN-FAIL/XFAIL KI-LOWDGRAM: peer max datagram limit ignored; "
              "pending owner/orchestrator decision; set NKR_TEST_LOWDGRAM=1 to reproduce")
BOUNDARIES = "^(TestFragmentBounds|TestWaitReadPacket|TestLowDatagram)"


def expected_outcomes(known=False, debug=False, boundaries=False):
    """Reviewed inventory, independent of the test execution being classified.

    Never learn expected tests from this run: a bypassed m.Run or removed subtest
    would otherwise redefine success. Inventory changes require a reviewed edit.
    Each entry is (terminal action, exact diagnostic), including allowed skips.
    """
    manifest = json.loads(Path(__file__).with_name("security-matrix-tests.json").read_text())
    expected = {}
    for package, tests in manifest["tests"].items():
        if (known or boundaries) and package not in {f"{MODULE}/{p}" for p in PROTOCOLS}:
            continue
        selected = {test: ("pass", None) for test in tests
                    if not boundaries or re.match(BOUNDARIES, test)}
        if debug and not (known or boundaries) and package == f"{MODULE}/hysteria":
            selected["TestDuplicateUDPSession"] = ("pass", None)
        if known:
            selected = {PARENT: ("fail", None)}
        for test in list(selected):
            if test in manifest["skips"]:
                selected[test] = ("skip", manifest["skips"][test])
        if package in {f"{MODULE}/{p}" for p in PROTOCOLS}:
            for api in ["false", "true"]:
                for size in [255, 256, 4096]:
                    test = f"{PARENT}/frame=64/packet={api}/size={size}"
                    selected[test] = ("fail", SIGNATURE) if known else ("skip", KNOWN_SKIP)
        expected[package] = selected
    return expected


def verify_package_inventory(listed, expected, no_tests):
    wanted = {p: "tests" for p in expected}
    wanted.update({p: "no-tests" for p in no_tests})
    observed = {}
    for line in listed.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in observed:
            raise RuntimeError("invalid/duplicate package inventory")
        observed[fields[0]] = fields[1]
    if observed != wanted:
        raise RuntimeError("package/test inventory changed; review the manifest")


def verify_outcome(transcript, binary_exits, expected, raw_by_package):
    """One fail-closed classifier for every PASS and XFAIL row.

    Require agreement among owned binary statuses, lossless raw/JSON output,
    exact test inventory, lifecycle actions, and the entire output grammar.
    There is no success shortcut for either expected outcome.
    """
    def reject(reason):
        raise RuntimeError(f"row outcome rejected: {reason}")

    packages = set(expected)
    wanted = {(p, t): action for p, tests in expected.items() for t, (action, _) in tests.items()}
    package_actions = {p: "fail" if any(a == "fail" for a, _ in tests.values()) else "pass"
                       for p, tests in expected.items()}
    if (not packages or any(not tests for tests in expected.values()) or
            not isinstance(binary_exits, dict) or set(binary_exits) != packages or
            any(type(code) is not int or code != (1 if package_actions[p] == "fail" else 0)
                for p, code in binary_exits.items())):
        reject(f"unexpected direct binary statuses: {binary_exits!r}")
    wanted.update({(p, None): a for p, a in package_actions.items()})
    states = {}
    output = defaultdict(str)
    by_package = defaultdict(list)
    for number, line in enumerate(transcript.splitlines(), 1):
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    reject(f"duplicate JSON field {key!r} at line {number}")
                result[key] = value
            return result
        try:
            event = json.loads(line, object_pairs_hook=unique_fields,
                               parse_constant=lambda value: reject(f"nonfinite JSON value: {value}"))
        except ValueError:
            reject(f"non-JSON output at line {number}: {line!r}")
        if not isinstance(event, dict):
            reject(f"invalid event at line {number}")
        package, test = event.get("Package"), event.get("Test")
        if (not isinstance(package, str) or package not in packages or
                ("Test" in event and not isinstance(test, str))):
            reject(f"unexpected package/test at line {number}")
        key = (package, test)
        if key not in wanted:
            reject(f"extra test: {key}")
        action = event.get("Action")
        if not isinstance(action, str):
            reject(f"invalid action at line {number}")
        if ("Elapsed" in event and (type(event["Elapsed"]) not in {int, float} or
                                    not math.isfinite(event["Elapsed"]) or event["Elapsed"] < 0)):
            reject(f"invalid elapsed time at line {number}")
        if "Time" in event and not isinstance(event["Time"], str):
            reject(f"invalid timestamp at line {number}")
        allowed = {"Action", "Package", "Test", "Time", "Elapsed"}
        if action == "output":
            allowed.add("Output")
        if set(event) - allowed:
            reject(f"unexpected event fields at line {number}")
        if test is not None:
            ancestors = [None] + [t for t in expected[package] if test.startswith(t + "/")]
            if any(states.get((package, t)) != "running" for t in ancestors):
                reject(f"test outside running parent/package: {key}")
        if action in {"pass", "fail", "skip"}:
            children = [t for t in expected[package] if test is None or t.startswith(test + "/")]
            if any(states.get((package, t)) != wanted[(package, t)] for t in children):
                reject(f"parent/package terminated before its children: {key}")
        if action == ("run" if test is not None else "start") and key not in states:
            states[key] = "running"
        elif action == "output" and states.get(key) == "running" and isinstance(event.get("Output"), str):
            output[key] += event["Output"]
        elif action == wanted[key] and states.get(key) == "running":
            states[key] = action
        else:
            reject(f"unexpected {action!r} event/state for {key} at line {number}")
        by_package[package].append(line)
    if states != wanted:
        reject("missing or incomplete package/test rows")
    duration = r"[0-9]+\.[0-9]+"
    for (package, test), action in wanted.items():
        if test is None:
            pattern = action.upper() + r"\n"
        else:
            diagnostic = expected[package][test][1]
            detail = (r"    [A-Za-z0-9_]+_test\.go:[0-9]+: " + re.escape(diagnostic) + r"\n"
                      if diagnostic is not None else "")
            if action == "fail" and diagnostic is not None:
                # The known defect must originate at the round-trip assertion.
                detail = (r"    low_datagram_test\.go:[0-9]+: " + re.escape(diagnostic) + r"\n")
            pattern = (rf"=== RUN   {re.escape(test)}\n" + detail +
                       rf"[ \t]*--- {action.upper()}: {re.escape(test)} \({duration}s\)\n")
        if not re.fullmatch(pattern, output[(package, test)]):
            reject(f"unexpected output for {package}/{test}: {output[(package, test)]!r}")
    if not isinstance(raw_by_package, dict) or set(raw_by_package) != packages:
        reject("missing/extra raw binary transcript")
    for package in packages:
        verify_conversion(raw_by_package[package], "\n".join(by_package[package]), expected[package])


LOW_DATAGRAM_SELECTION = "^TestLowDatagramRoundTrip/frame=64/packet=.*/size=(255|256|4096)$"


def capture_command(cmd, log, cwd, env, records, timeout=300, stdin=None):
    """Capture an owned process directly; record its real status and deadline."""
    cmd = [str(x) for x in cmd]
    record = {"command": cmd, "cwd": str(cwd), "timeout_seconds": timeout,
              "log": str(log), "stdin": str(stdin) if stdin else None,
              "environment": {k: env.get(k) for k in
                              ["GOTOOLCHAIN", "GOWORK", "GOFLAGS", "CGO_ENABLED", "NKR_TEST_LOWDGRAM", "GORACE"]}}
    records.append(record)
    start = time.monotonic()
    with log.open("wb") as stream:
        source = stdin.open("rb") if stdin else subprocess.DEVNULL
        try:
            process = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=source, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                record["exit"] = process.wait(timeout=timeout)
                record["timed_out"] = False
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                record["exit"] = process.returncode
                record["timed_out"] = True
        finally:
            if stdin:
                source.close()
    record["seconds"] = round(time.monotonic() - start, 3)
    return record


def require_success(record):
    if record["exit"] != 0 or record["timed_out"]:
        raise RuntimeError(f"command exit {record['exit']} (timeout={record['timed_out']}): "
                           f"{shlex.join(record['command'])}; see {record['log']}")


def verify_conversion(raw, transcript, tests):
    """Ensure the converter discarded no diagnostics or undecodable bytes.

    Go's test2json framing removes line-leading ^V markers and NAME controls;
    only NAME controls for this selection (or its empty reset) are allowed.
    Every other byte must survive in the JSON Output events in source order.
    """
    try:
        text = raw.decode("utf-8", errors="strict")
        events = [json.loads(line) for line in transcript.splitlines()]
        decoded = "".join(e.get("Output", "") for e in events)
    except (UnicodeError, ValueError, AttributeError, TypeError) as error:
        raise RuntimeError("invalid test output/converter transcript") from error
    # NAME controls after the final record must not disappear unnoticed.
    if not text.endswith(("PASS\n", "FAIL\n")):
        raise RuntimeError("raw binary transcript lacks a final PASS/FAIL record")
    name = r"=== NAME  (?:" + "|".join(re.escape(t) for t in tests) + r")?\n"
    expected = []
    for line in text.splitlines(keepends=True):
        if line.startswith("\x16"):
            line = line[1:]
        if re.fullmatch(name, line):
            continue
        expected.append(line)
    if "".join(expected) != decoded:
        raise RuntimeError("raw test output and JSON output disagree")


def run_row(go, root, out, prefix, mod, env, records, expected, flags=(), selection=None,
            timeout=300, binary_timeout=300, test_timeout="180s"):
    """Every row builds fresh binaries, owns their execution, and classifies once."""
    exits, raws, transcripts = {}, {}, []
    linker = ["-ldflags=-linkmode=external"] if sys.platform == "darwin" else []
    for package in expected:
        relative = package.removeprefix(MODULE + "/")
        stem = f"{prefix}-{relative.replace('/', '-')}"
        binary = out / f"{stem}.test"
        # Never execute a leftover executable, even if a compiler exits 0 but
        # fails to create its requested output.
        binary.unlink(missing_ok=True)
        build_log = out / f"{stem}-build.log"
        build = capture_command([go, "test", "-c", *mod, *linker, *flags, "-o", binary, f"./{relative}"],
                                build_log, root, env, records, timeout)
        require_success(build)
        if build_log.read_bytes():
            raise RuntimeError(f"unexpected build output; see {build_log}")
        raw = out / f"{stem}-binary.log"
        cmd = [binary, "-test.v=test2json", "-test.count=1", f"-test.timeout={test_timeout}"]
        if selection:
            cmd.append(f"-test.run={selection}")
        run = capture_command(cmd, raw, root, env, records, binary_timeout)
        if run["timed_out"]:
            raise RuntimeError(f"test binary timed out; see {raw}")
        exits[package] = run["exit"]
        raws[package] = raw.read_bytes()
        converted = out / f"{stem}.jsonl"
        conversion = capture_command([go, "tool", "test2json", "-p", package],
                                     converted, root, env, records, timeout, stdin=raw)
        require_success(conversion)
        transcripts.append(converted.read_text())
    transcript = "".join(transcripts)
    (out / f"{prefix}.jsonl").write_text(transcript)
    (out / f"{prefix}-binary-exits.json").write_text(json.dumps(exits, indent=2) + "\n")
    verify_outcome(transcript, exits, expected, raws)
    return exits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies", choices=["standalone", "shipped", "all"], default="all")
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    go = shutil.which(args.go)
    if not go:
        parser.error("Go executable not found")
    env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly", CGO_ENABLED="1")
    # Default rows always record the known-failure skips, even in an opt-in shell.
    env.pop("NKR_TEST_LOWDGRAM", None)
    env.pop("NKR_STRESS_STREAMS", None)
    rows = []
    metadata = {"platform": platform.platform(), "commands": [], "rows": rows}

    def command(cmd, log, cwd=root, command_env=env, timeout=300):
        record = capture_command(cmd, out / log, cwd, command_env, metadata["commands"], timeout)
        require_success(record)
        return (out / log).read_text()

    def fetch(name, url, sha):
        directory = out / name
        command(["git", "init", directory], f"{name}-init.log")
        command(["git", "fetch", "--depth=1", url, sha], f"{name}-fetch.log", directory, timeout=180)
        command(["git", "checkout", "--detach", "FETCH_HEAD"], f"{name}-checkout.log", directory)
        actual = command(["git", "rev-parse", "HEAD"], f"{name}-head.log", directory).strip()
        if actual != sha:
            raise RuntimeError(f"{name} pin mismatch: {actual}")
        return directory

    def overlay():
        nekoray = fetch("nekoray", "https://github.com/ad1896git/nekoray.git", NEKORAY)
        pins = (nekoray / "libs/get_source_env.sh").read_text()
        for name, sha in [("SING_QUIC", SING_QUIC), ("QUIC_GO", QUIC)]:
            if f'COMMIT_{name}="{sha}"' not in pins:
                raise RuntimeError(f"nekoray {name} pin mismatch")
        core = (nekoray / "go/cmd/nekobox_core/go.mod").read_text()
        if ("github.com/sagernet/sing v0.4.3" not in core or
                "github.com/sagernet/quic-go v0.47.0-beta.2" not in core or
                "replace github.com/sagernet/quic-go => ../../../../quic-go" not in core):
            raise RuntimeError("nekoray dependency/replace directives changed")
        patch = nekoray / PATCH
        if hashlib.sha256(patch.read_bytes()).hexdigest() != PATCH_SHA256:
            raise RuntimeError("nekoray congestion patch digest mismatch")
        quic = fetch("quic-go", "https://github.com/sagernet/quic-go.git", QUIC)
        command(["git", "apply", "--check", patch], "patch-check.log", quic)
        command(["git", "apply", patch], "patch-apply.log", quic)
        command(["git", "apply", "--reverse", "--check", patch], "patch-reverse-check.log", quic)
        modfile = out / "shipped.mod"
        shutil.copyfile(root / "go.mod", modfile)
        shutil.copyfile(root / "go.sum", out / "shipped.sum")
        command([go, "mod", "edit", f"-modfile={modfile}",
                 "-require=github.com/sagernet/sing@v0.4.3",
                 "-require=github.com/sagernet/quic-go@v0.47.0-beta.2",
                 f"-replace=github.com/sagernet/quic-go={quic}"], "overlay-edit.log")
        command([go, "mod", "tidy", f"-modfile={modfile}"], "overlay-tidy.log")
        return [f"-modfile={modfile}"]

    def test_row(dependency, name, mod, flags, known=False):
        row = {"name": f"{dependency}/{name}", "result": "FAIL", "skips": []}
        rows.append(row)
        prefix = f"{dependency}-{name}"
        test_env = dict(env, NKR_TEST_LOWDGRAM="1") if known else env
        boundaries = name == "boundaries"
        expected = expected_outcomes(known=known, debug="debug" in name, boundaries=boundaries)
        build_flags = [f for f in flags if f.startswith("-tags=") or f == "-race"]
        selection = LOW_DATAGRAM_SELECTION if known else BOUNDARIES if boundaries else None
        if not (known or boundaries):
            # Check the entire package inventory (including packages without
            # tests) independently, and compile every package under these flags.
            manifest = json.loads((root / "scripts/security-matrix-tests.json").read_text())
            listed = command([go, "list", *mod, *build_flags, "-f",
                              "{{.ImportPath}} {{if or .TestGoFiles .XTestGoFiles}}tests{{else}}no-tests{{end}}",
                              "./..."], f"{prefix}-packages.log")
            verify_package_inventory(listed, expected, manifest["no_tests"])
            command([go, "build", *mod, *build_flags, "./..."], f"{prefix}-build-all.log")
            row["skips"] += [{"package": p, "test": None, "reason": "[no test files]"}
                             for p in manifest["no_tests"]]
        row["evidence"] = f"{prefix}.jsonl"
        row["binary_exits"] = run_row(go, root, out, prefix, mod, test_env, metadata["commands"],
                                      expected, build_flags, selection)
        row["skips"] += [{"package": p, "test": t, "reason": diagnostic}
                         for p, tests in expected.items() for t, (action, diagnostic) in tests.items()
                         if action == "skip"]
        row["result"] = "XFAIL (18 reproduced; each binary exits 1)" if known else "PASS"
        print(f"{row['name']}: {row['result']}; skips={len(row['skips'])}", flush=True)

    try:
        command([sys.executable, "-B", "-m", "unittest", "discover", "-s", "scripts",
                 "-p", "test_security_matrix.py", "-v"], "verifier-self-tests.log",
                command_env=dict(env, SEC_MATRIX_GO=go))
        version = command([go, "version"], "go-version.log").strip()
        if " go1.22.12 " not in version:
            raise RuntimeError(f"required Go 1.22.12, got {version}")
        metadata["head"] = command(["git", "rev-parse", "HEAD"], "head.log").strip()
        dependencies = ["standalone", "shipped"] if args.dependencies == "all" else [args.dependencies]
        for dependency in dependencies:
            mod = overlay() if dependency == "shipped" else []
            graph = command([go, "list", *mod, "-m", "all"], f"{dependency}-modules.log")
            if any(line.startswith("github.com/sagernet/sing v0.5.") for line in graph.splitlines()):
                raise RuntimeError("sing v0.5 is outside this matrix")
            for tags in ["", "debug", "with_low_memory", "debug,with_low_memory"]:
                for race in [False, True]:
                    flags = ([f"-tags={tags}"] if tags else []) + (["-race"] if race else [])
                    name = (tags.replace(",", "-") or "standard") + ("-race" if race else "")
                    test_row(dependency, name, mod, flags)
            test_row(dependency, "boundaries", mod, ["-race", "-tags=debug,with_low_memory"])
            test_row(dependency, "known-low-datagram", mod, [], known=True)
    except (RuntimeError, OSError) as error:
        metadata["error"] = str(error)
        print(error, file=sys.stderr)
    finally:
        (out / "results.json").write_text(json.dumps(metadata, indent=2) + "\n")
        lines = ["| Row | Result | Skips |", "| --- | --- | --- |"]
        lines += [f"| {r['name']} | {r['result']} | {len(r['skips'])} |" for r in rows]
        (out / "results.md").write_text("\n".join(lines) + "\n")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as stream:
                stream.write("\n".join(lines) + "\n")
    return 1 if "error" in metadata else 0


if __name__ == "__main__":
    sys.exit(main())
