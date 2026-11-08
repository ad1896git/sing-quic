#!/usr/bin/env python3
"""Run the SEC-MATRIX with bounded commands and inspectable per-row evidence."""

import argparse
from collections import defaultdict
import hashlib
import json
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


def verify_known_failure(transcript, binary_exits):
    """Accept only the complete, named KI-LOWDGRAM failure transcript.

    Allowlist output as well as events: Go can emit a TestMain/background panic
    after all expected leaves fail, without adding another failing test event.
    Unknown output (including non-JSON stderr) must therefore fail closed.
    """
    def reject(reason):
        raise RuntimeError(f"known-failure result changed: {reason}")

    parent = "TestLowDatagramRoundTrip"
    leaves = {f"{parent}/frame=64/packet={api}/size={size}"
              for api in ["false", "true"] for size in [255, 256, 4096]}
    packages = {f"github.com/sagernet/sing-quic/{p}" for p in PROTOCOLS}
    # These are Popen.wait() results from the binaries themselves, never the
    # normalized status of go test or test2json. Require all three sources.
    if (not isinstance(binary_exits, dict) or set(binary_exits) != packages or
            any(type(code) is not int or code != 1 for code in binary_exits.values())):
        reject(f"expected each test binary to exit 1, got {binary_exits!r}")
    expected = {(p, t) for p in packages for t in leaves | {parent}}
    # Each package/test must start once, fail once, and emit only its expected
    # transcript between those events. Sets alone would hide duplicate rows.
    states = {}
    output = defaultdict(str)
    for number, line in enumerate(transcript.splitlines(), 1):
        try:
            def unique_fields(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        reject(f"duplicate JSON field {key!r} at line {number}")
                    result[key] = value
                return result
            event = json.loads(line, object_pairs_hook=unique_fields)
        except ValueError:
            reject(f"non-JSON output at line {number}: {line!r}")
        if not isinstance(event, dict):
            reject(f"invalid event at line {number}")
        package, test = event.get("Package"), event.get("Test")
        if (not isinstance(package, str) or package not in packages or
                ("Test" in event and (not isinstance(test, str) or (package, test) not in expected))):
            reject(f"unexpected package/test at line {number}: {package!r}/{test!r}")
        key = (package, test)
        action = event.get("Action")
        allowed = {"Action", "Package", "Test", "Time", "Elapsed"}
        if action == "output":
            allowed.add("Output")
        if set(event) - allowed:
            reject(f"unexpected event fields at line {number}")
        if test is not None and states.get((package, None)) != "running":
            reject(f"test event outside running package: {key}")
        if test in leaves and states.get((package, parent)) != "running":
            reject(f"leaf event outside running parent: {key}")
        if action == "fail" and test in {None, parent}:
            children = leaves if test == parent else leaves | {parent}
            if any(states.get((package, child)) != "failed" for child in children):
                reject(f"parent/package failed before its children: {key}")
        if action == ("run" if test is not None else "start") and key not in states:
            states[key] = "running"
        elif action == "output" and states.get(key) == "running" and isinstance(event.get("Output"), str):
            output[key] += event["Output"]
        elif action == "fail" and states.get(key) == "running":
            states[key] = "failed"
        else:
            reject(f"unexpected {action!r} event/state for {key} at line {number}")
    all_keys = expected | {(p, None) for p in packages}
    if set(states) != all_keys or any(s != "failed" for s in states.values()):
        reject("missing or incomplete package/test rows")
    duration = r"[0-9]+\.[0-9]+"
    for package, test in all_keys:
        if test is None:
            pattern = r"FAIL\n"
        else:
            diagnostic = (r"    low_datagram_test\.go:[0-9]+: "
                          r"PROTOCOL_VIOLATION \(local\): DATAGRAM frame too large\n") if test in leaves else ""
            pattern = (rf"=== RUN   {re.escape(test)}\n" + diagnostic +
                       rf"[ \t]*--- FAIL: {re.escape(test)} \({duration}s\)\n")
        if not re.fullmatch(pattern, output[(package, test)]):
            reject(f"unexpected output for {package}/{test}: {output[(package, test)]!r}")


LOW_DATAGRAM_SELECTION = "^TestLowDatagramRoundTrip/frame=64/packet=.*/size=(255|256|4096)$"


def capture_command(cmd, log, cwd, env, records, timeout=300, stdin=None):
    """Capture an owned process directly; record its real status and deadline."""
    cmd = [str(x) for x in cmd]
    record = {"command": cmd, "cwd": str(cwd), "timeout_seconds": timeout,
              "log": str(log), "stdin": str(stdin) if stdin else None,
              "environment": {k: env.get(k) for k in
                              ["GOTOOLCHAIN", "GOWORK", "GOFLAGS", "CGO_ENABLED", "NKR_TEST_LOWDGRAM"]}}
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


def verify_conversion(raw, transcript):
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
    name = (r"=== NAME  (?:TestLowDatagramRoundTrip"
            r"(?:/frame=64/packet=(?:false|true)/size=(?:255|256|4096))?)?\n")
    expected = []
    for line in text.splitlines(keepends=True):
        if line.startswith("\x16"):
            line = line[1:]
        if re.fullmatch(name, line):
            continue
        expected.append(line)
    if "".join(expected) != decoded:
        raise RuntimeError("raw test output and JSON output disagree")


def run_known_failure(go, root, out, prefix, mod, env, records, timeout=300,
                      binary_timeout=300, test_timeout="180s"):
    """Build, directly execute, then decode each binary's captured output.

    test2json only reads a completed raw log from stdin: it never owns a test
    process and cannot normalize its status. The verdict requires the captured
    OS statuses AND the exact decoded lifecycle/output to agree. No shell/pipe.
    """
    exits = {}
    transcripts = []
    linker = ["-ldflags=-linkmode=external"] if sys.platform == "darwin" else []
    for protocol in PROTOCOLS:
        stem = f"{prefix}-{protocol}"
        binary = out / f"{stem}.test"
        build_log = out / f"{stem}-build.log"
        build = capture_command([go, "test", "-c", *mod, *linker, "-o", binary, f"./{protocol}"],
                                build_log, root, env, records, timeout)
        require_success(build)
        if build_log.read_bytes():
            raise RuntimeError(f"unexpected build output; see {build_log}")
        raw = out / f"{stem}-binary.log"
        run = capture_command([binary, "-test.v=test2json", "-test.count=1",
                               f"-test.timeout={test_timeout}", f"-test.run={LOW_DATAGRAM_SELECTION}"],
                              raw, root, env, records, binary_timeout)
        if run["timed_out"]:
            raise RuntimeError(f"test binary timed out; see {raw}")
        package = f"github.com/sagernet/sing-quic/{protocol}"
        exits[package] = run["exit"]
        converted = out / f"{stem}.jsonl"
        conversion = capture_command([go, "tool", "test2json", "-p", package],
                                     converted, root, env, records, timeout, stdin=raw)
        require_success(conversion)
        decoded = converted.read_text()
        verify_conversion(raw.read_bytes(), decoded)
        transcripts.append(decoded)
    transcript = "".join(transcripts)
    (out / f"{prefix}.jsonl").write_text(transcript)
    (out / f"{prefix}-binary-exits.json").write_text(json.dumps(exits, indent=2) + "\n")
    verify_known_failure(transcript, exits)
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

    def test_row(dependency, name, mod, flags, packages, known=False):
        row = {"name": f"{dependency}/{name}", "result": "FAIL", "skips": []}
        rows.append(row)
        filename = f"{dependency}-{name}.jsonl"
        test_env = dict(env, NKR_TEST_LOWDGRAM="1") if known else env
        row["evidence"] = filename
        if known:
            row["binary_exits"] = run_known_failure(
                go, root, out, f"{dependency}-{name}", mod, test_env, metadata["commands"])
            row["result"] = "XFAIL (18 reproduced; each binary exits 1)"
        else:
            # macOS 27 rejects Go 1.22 internal-linked binaries without LC_UUID.
            linker = ["-ldflags=-linkmode=external"] if sys.platform == "darwin" else []
            cmd = [go, "test", *mod, *linker, "-json", "-count=1", "-timeout=180s", *flags, *packages]
            row["command"] = cmd
            transcript = command(cmd, filename, command_env=test_env)
            events = []
            for line in transcript.splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
            if not any(e.get("Action") == "pass" and "Test" not in e for e in events):
                raise RuntimeError(f"no package pass events in {filename}")
            for e in events:
                if e.get("Action") == "skip":
                    reason = "".join(x.get("Output", "") for x in events
                                     if x.get("Package") == e["Package"] and x.get("Test") == e.get("Test")
                                     and x.get("Action") == "output").strip()
                    row["skips"].append({"package": e["Package"], "test": e.get("Test"), "reason": reason})
            row["result"] = "PASS"
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
                    test_row(dependency, name, mod, flags, ["./..."])
            test_row(dependency, "boundaries", mod,
                     ["-race", "-tags=debug,with_low_memory", "-run",
                      "^(TestFragmentBounds|TestWaitReadPacket|TestLowDatagram)"],
                     [f"./{p}" for p in PROTOCOLS])
            test_row(dependency, "known-low-datagram", mod,
                     ["-run", LOW_DATAGRAM_SELECTION],
                     [f"./{p}" for p in PROTOCOLS], known=True)
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
