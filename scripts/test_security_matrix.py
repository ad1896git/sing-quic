"""The same adversarial contracts gate PASS and XFAIL rows in CI."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("security_matrix", Path(__file__).with_name("security-matrix.py"))
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)
PARENT = MATRIX.PARENT
PACKAGE = MATRIX.MODULE + "/hysteria"
LEAF = PARENT + "/frame=64/packet=false/size=255"
SIGNATURE = MATRIX.SIGNATURE


def expected(known):
    return {f"{MATRIX.MODULE}/{p}": {
        PARENT: ("fail" if known else "pass", None),
        **{f"{PARENT}/frame=64/packet={api}/size={size}":
           ("fail", SIGNATURE) if known else ("pass", None)
           for api in ["false", "true"] for size in [255, 256, 4096]}}
        for p in MATRIX.PROTOCOLS}


def fixture(known):
    events = []
    def event(action, package, test=None, output=None):
        item = {"Action": action, "Package": package}
        if test is not None:
            item["Test"] = test
        if output is not None:
            item["Output"] = output
        events.append(item)
    for package, tests in expected(known).items():
        event("start", package)
        event("run", package, PARENT)
        event("output", package, PARENT, f"=== RUN   {PARENT}\n")
        for test, (action, diagnostic) in tests.items():
            if test == PARENT:
                continue
            event("run", package, test)
            event("output", package, test, f"=== RUN   {test}\n")
            if diagnostic:
                event("output", package, test, f"    low_datagram_test.go:73: {diagnostic}\n")
            event("output", package, test, f"--- {action.upper()}: {test} (0.01s)\n")
            event(action, package, test)
        action = "fail" if known else "pass"
        event("output", package, PARENT, f"--- {action.upper()}: {PARENT} (0.10s)\n")
        event(action, package, PARENT)
        event("output", package, output=action.upper() + "\n")
        event(action, package)
    return events


def transcript(events):
    return "".join(json.dumps(e) + "\n" for e in events)


def raw_output(events):
    return {p: "".join(e.get("Output", "") for e in events if e.get("Package") == p).encode()
            for p in expected(False)}


class SharedClassifierTests(unittest.TestCase):
    def verify(self, known, events=None, exits=None, raw=None, wanted=None, text=None):
        events = fixture(known) if events is None else events
        MATRIX.verify_outcome(transcript(events) if text is None else text,
                              {p: int(known) for p in expected(known)} if exits is None else exits,
                              expected(known) if wanted is None else wanted,
                              raw_output(events) if raw is None else raw)

    def test_controls_interleaving_and_chunking(self):
        for known in [False, True]:
            self.verify(known)
            groups = [[e for e in fixture(known) if e['Package'] == p] for p in expected(known)]
            interleaved = [e for group in zip(*groups) for e in group]
            split = []
            for e in interleaved:
                split += [dict(e, Output=c) for c in e['Output']] if e['Action'] == 'output' else [e]
            self.verify(known, split)

    def test_direct_status_agreement(self):
        for known in [False, True]:
            for code in [0, 1, 2, 66, 124, -9, -15, True, '1', None]:
                if type(code) is int and code == int(known):
                    continue
                exits = {p: int(known) for p in expected(known)}
                exits[PACKAGE] = code
                with self.subTest(known=known, exit=code), self.assertRaises(RuntimeError):
                    self.verify(known, exits=exits)
            for exits in [1, {}, {PACKAGE: int(known)}, dict(exits, extra=1)]:
                with self.subTest(known=known, exits=exits), self.assertRaises(RuntimeError):
                    self.verify(known, exits=exits)

    def test_malformed_and_raw_output(self):
        for known in [False, True]:
            for text in ['', '\n', 'null\n', '[]\n', '{}\n', '{broken\n',
                         transcript(fixture(known)) + 'panic: process failure\n',
                         '# build error\n' + transcript(fixture(known))]:
                with self.subTest(known=known, text=text[-80:]), self.assertRaises(RuntimeError):
                    self.verify(known, text=text)

    def test_diagnostics_at_every_scope(self):
        for known in [False, True]:
            for diagnostic in ['panic: unrelated process panic', 'fatal error: concurrent map writes',
                               'WARNING: DATA RACE', 'panic: test timed out after 3m0s',
                               'FAIL [build failed]', 'exit status 2', 'unexpected cleanup error',
                               SIGNATURE, '    low_datagram_test.go:77: assertion failed']:
                for test in [None, PARENT, LEAF]:
                    events = fixture(known)
                    index = next(i for i, e in enumerate(events)
                                 if e['Package'] == PACKAGE and e.get('Test') == test
                                 and e['Action'] in ['pass', 'fail'])
                    extra = {'Action': 'output', 'Package': PACKAGE, 'Output': diagnostic + '\n'}
                    if test is not None:
                        extra['Test'] = test
                    events.insert(index, extra)
                    with self.subTest(known=known, diagnostic=diagnostic, scope=test), self.assertRaises(RuntimeError):
                        self.verify(known, events)

    def test_changed_or_misattributed_diagnostic(self):
        for known in [False, True]:
            for error in ['DATAGRAM frame too large', 'INTERNAL_ERROR (local): DATAGRAM frame too large',
                          'PROTOCOL_VIOLATION (local): unrelated transport failure',
                          'PROTOCOL_VIOLATION (remote): DATAGRAM frame too large',
                          'context deadline exceeded', SIGNATURE + ': extra cause', '']:
                events = fixture(known)
                index = next(i for i,e in enumerate(events) if e.get('Test') == LEAF and e['Action'] == 'output') + 1
                if known:
                    events[index]['Output'] = f'    low_datagram_test.go:73: {error}\n'
                else:
                    events.insert(index, {'Package': PACKAGE, 'Test': LEAF, 'Action': 'output',
                                          'Output': f'    low_datagram_test.go:73: {error}\n'})
                with self.subTest(known=known, error=error), self.assertRaises(RuntimeError):
                    self.verify(known, events)
            events = fixture(known)
            target = next(e for e in events if e.get('Test') == LEAF and e['Action'] == 'output')
            target.pop('Test')
            with self.subTest(known=known, attribution=True), self.assertRaises(RuntimeError):
                self.verify(known, events)

    def test_missing_extra_duplicate_or_changed_outcomes(self):
        for known in [False, True]:
            for scope in [LEAF, PARENT, None]:
                for mutation in ['missing', 'extra', 'duplicate', 'pass', 'fail', 'skip']:
                    if mutation == ('fail' if known else 'pass'):
                        continue
                    events = fixture(known)
                    selected = lambda e: e['Package'] == PACKAGE and (scope is None or e.get('Test') == scope)
                    if mutation == 'missing':
                        events = [e for e in events if not selected(e)]
                    elif mutation in ['extra', 'duplicate']:
                        extra = copy.deepcopy([e for e in events if selected(e)])
                        if mutation == 'extra':
                            for e in extra:
                                if scope is None:
                                    e['Package'] += '-extra'
                                else:
                                    e['Test'] += '-extra'
                        events[3:3] = extra
                    else:
                        target = next(e for e in events if e['Package'] == PACKAGE and e.get('Test') == scope
                                      and e['Action'] == ('fail' if known else 'pass'))
                        target['Action'] = mutation
                    with self.subTest(known=known, scope=scope, mutation=mutation), self.assertRaises(RuntimeError):
                        self.verify(known, events)

    def test_unexpected_assertion_even_when_package_passes(self):
        # dr2: real fail actions must never be masked by package success/exit 0.
        for known in [False, True]:
            events = fixture(known)
            leaf = next(e for e in events if e.get('Test') == LEAF and e['Action'] in ['pass','fail'])
            leaf['Action'] = 'fail'
            package = next(e for e in events if e['Package'] == PACKAGE and 'Test' not in e and e['Action'] in ['pass','fail'])
            package['Action'] = 'pass'
            with self.subTest(known=known), self.assertRaises(RuntimeError):
                self.verify(known, events)

    def test_skip_requires_exact_expected_reason(self):
        for known in [False, True]:
            wanted = expected(known)
            wanted[PACKAGE][LEAF] = ('skip', 'reviewed skip reason')
            events = fixture(known)
            for e in events:
                if e['Package'] == PACKAGE and e.get('Test') == LEAF:
                    if e['Action'] in ['pass', 'fail']:
                        e['Action'] = 'skip'
                    elif e['Action'] == 'output' and e['Output'].startswith('---'):
                        e['Output'] = f'--- SKIP: {LEAF} (0.01s)\n'
            events = [e for e in events if not (e['Package'] == PACKAGE and e.get('Test') == LEAF
                      and 'low_datagram_test.go:' in e.get('Output', ''))]
            index = next(i for i,e in enumerate(events) if e.get('Test') == LEAF and e['Action'] == 'skip') - 1
            events.insert(index, {'Action': 'output', 'Package': PACKAGE, 'Test': LEAF,
                                  'Output': '    low_datagram_test.go:73: reviewed skip reason\n'})
            self.verify(known, events, wanted=wanted)
            events[index]['Output'] = '    low_datagram_test.go:73: other skip\n'
            with self.subTest(known=known), self.assertRaises(RuntimeError):
                self.verify(known, events, wanted=wanted)

    def test_corrupt_lifecycles_and_fields(self):
        for known in [False, True]:
            for corruption in ['unknown-action','unknown-field','hidden-output','late-output',
                               'early-parent','early-package','truncated','wrong-package','duplicate-output',
                               'invalid-action','invalid-elapsed','nonfinite-elapsed','invalid-time']:
                events = fixture(known)
                target = next(e for e in events if e['Action'] == 'run' and e.get('Test') == LEAF)
                if corruption == 'unknown-action': target['Action'] = 'pause'
                elif corruption == 'unknown-field': target['Error'] = 'hidden error'
                elif corruption == 'invalid-action': target['Action'] = []
                elif corruption == 'invalid-elapsed': target['Elapsed'] = True
                elif corruption == 'nonfinite-elapsed': target['Elapsed'] = float('nan')
                elif corruption == 'invalid-time': target['Time'] = {}
                elif corruption == 'hidden-output': target['Output'] = 'panic: hidden error'
                elif corruption == 'late-output': events.append({'Action':'output','Package':PACKAGE,'Output':'error'})
                elif corruption in ['early-parent','early-package']:
                    test = PARENT if corruption == 'early-parent' else None
                    terminal = next(e for e in events if e['Action'] in ['pass','fail'] and e.get('Test') == test)
                    events.remove(terminal)
                    events.insert(3,terminal)
                elif corruption == 'truncated': events.pop()
                elif corruption == 'wrong-package': target['Package'] = 'example.org/other'
                else: events.insert(4,copy.deepcopy(events[4]))
                with self.subTest(known=known, corruption=corruption), self.assertRaises(RuntimeError):
                    self.verify(known,events)
            text = transcript(fixture(known)).replace('"Action": "start"','"Action": "pass", "Action": "start"',1)
            with self.subTest(known=known), self.assertRaisesRegex(RuntimeError,'duplicate JSON field'):
                self.verify(known,text=text)

    def test_raw_json_conservation(self):
        for known in [False, True]:
            for suffix in [b'cleanup error\n', b'\xff\n', b'\x16=== NAME  unrelated\n',
                           b'\x16=== NAME  TestLowDatagramRoundTrip\n', b'\x16=== NAME  \n']:
                raw = raw_output(fixture(known))
                raw[PACKAGE] += suffix
                with self.subTest(known=known, suffix=suffix), self.assertRaises(RuntimeError):
                    self.verify(known,raw=raw)
            for prefix in [b'lost cleanup error\n', b'\x16=== NAME  unrelated\n']:
                raw = raw_output(fixture(known))
                raw[PACKAGE] = prefix + raw[PACKAGE]
                with self.subTest(known=known, prefix=prefix), self.assertRaises(RuntimeError):
                    self.verify(known,raw=raw)
            for raw in [{}, {PACKAGE:b''}, dict(raw_output(fixture(known)),extra=b''),
                        {p:b'' for p in expected(known)}]:
                with self.subTest(known=known,raw=raw), self.assertRaises(RuntimeError):
                    self.verify(known,raw=raw)
            raw = raw_output(fixture(known))
            raw[PACKAGE] = b'\x16=== NAME  \n' + raw[PACKAGE]
            self.verify(known,raw=raw)

    def test_package_inventory(self):
        for known in [False, True]:
            wanted = expected(known)
            no_tests = [MATRIX.MODULE + "/empty"]
            listed = "".join(p + " tests\n" for p in wanted) + no_tests[0] + " no-tests\n"
            MATRIX.verify_package_inventory(listed, wanted, no_tests)
            for bad in ["", listed + listed, listed + "extra tests\n",
                        listed.replace(" no-tests", " tests"),
                        listed.replace(" tests", " no-tests", 1), listed + "broken\n"]:
                with self.subTest(known=known, listed=bad), self.assertRaises(RuntimeError):
                    MATRIX.verify_package_inventory(bad, wanted, no_tests)

    def test_manifest_pins_all_datagram_assertions(self):
        for debug in [False, True]:
            for boundaries in [False,True]:
                wanted = MATRIX.expected_outcomes(debug=debug,boundaries=boundaries)
                for protocol in MATRIX.PROTOCOLS:
                    tests = wanted[f'{MATRIX.MODULE}/{protocol}']
                    datagrams = {t:a for t,(a,_) in tests.items() if t.startswith(PARENT+'/')}
                    self.assertEqual(len(datagrams),32)
                    self.assertEqual(sum(a=='pass' for a in datagrams.values()),26)
                    self.assertEqual(sum(a=='skip' for a in datagrams.values()),6)
        self.assertEqual(MATRIX.expected_outcomes(known=True),expected(True))


PROBE_SOURCE = '''package probe
import ("fmt"; "os"; "testing"; "time"; "syscall"; "sync")
var mode = os.Getenv("SEC_MATRIX_PROBE")
var known = os.Getenv("SEC_MATRIX_EXPECTED") == "xfail"
func init() {
    if mode == "init0" { os.Exit(0) }
    if mode == "init1" { os.Exit(1) }
}
func TestLowDatagramRoundTrip(t *testing.T) {
    if mode == "no-tests" { return }
    for _, api := range []bool{false, true} {
        for _, size := range []int{255,256,4096} {
            t.Run(fmt.Sprintf("frame=64/packet=%t/size=%d",api,size),func(t *testing.T) {
                if mode == "skip" { t.Skip("unexpected skip") }
                if known { t.Error("PROTOCOL_VIOLATION (local): DATAGRAM frame too large") }
                if mode == "assert" || mode == "assert0" { t.Error("real failed assertion") }
                if mode == "fatal" { t.Fatal("real fatal assertion") }
                if mode == "goroutine-assert" {
                    done:=make(chan struct{}); go func(){ defer close(done); t.Error("background assertion") }(); <-done
                }
                if mode == "timeout" { time.Sleep(time.Hour) }
                if mode == "race0" {
                    var n int; var wg sync.WaitGroup; wg.Add(2)
                    for i:=0;i<2;i++ { go func(){ defer wg.Done(); for j:=0;j<10000;j++ {n++} }() }; wg.Wait()
                }
                // A positive assertion also exercises the PASS control.
                if size < 255 { t.Fatal("invalid probe size") }
            })
        }
    }
}
func TestMain(m *testing.M) {
    if mode == "skip-all" { os.Exit(0) }
    code:=m.Run()
    switch mode {
    case "trailing-output": fmt.Fprintln(os.Stderr,"unrelated cleanup error")
    case "exit2": os.Exit(2)
    case "exit0","assert0","race0": os.Exit(0)
    case "panic": panic("unrelated post-test process panic")
    case "goroutine-panic": go func(){panic("unrelated background panic")}(); time.Sleep(time.Hour)
    case "hang": time.Sleep(time.Hour)
    case "signal": syscall.Kill(os.Getpid(),syscall.SIGKILL)
    }
    os.Exit(code)
}
'''


class RealProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='.verifier-probe-',dir=Path(__file__).parent)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name).resolve()
        (cls.root/'go.mod').write_text(f'module {MATRIX.MODULE}\n\ngo 1.22\n')
        for protocol in MATRIX.PROTOCOLS:
            (cls.root/protocol).mkdir()
            (cls.root/protocol/'low_datagram_test.go').write_text(PROBE_SOURCE)
        cls.go = os.environ.get('SEC_MATRIX_GO','go')
        cls.env = dict(os.environ,GOTOOLCHAIN='local',GOWORK='off',GOFLAGS='-mod=readonly',CGO_ENABLED='1')
        cls.number = 0

    def probe(self, known, mode, reject=True, go=None, flags=(), all_packages=False, stale=False, build_failure=False):
        type(self).number += 1
        out = self.root/f'{self.number}-{known}-{mode}'
        out.mkdir()
        if stale:
            binary = out/'probe-hysteria.test'
            binary.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(out / "stale-executed")!r}).touch()\n')
            binary.chmod(0o700)
        wanted = expected(known) if all_packages else {PACKAGE: expected(known)[PACKAGE]}
        env = dict(self.env,SEC_MATRIX_EXPECTED='xfail' if known else 'pass',SEC_MATRIX_PROBE=mode)
        if mode == 'race0':
            env['GORACE'] = 'exitcode=0'
        records = []
        def run():
            return MATRIX.run_row(go or self.go,self.root,out,'probe',[],env,records,wanted,
                                  flags=flags,binary_timeout=2 if mode=='hang' else 10,test_timeout='1s')
        try:
            if reject:
                with self.assertRaises((RuntimeError,OSError)):
                    run()
            else:
                self.assertEqual(run(),{p:int(known) for p in wanted})
        finally:
            print(f'real probe {known=} {mode=}: '+json.dumps([
                {'command':r['command'],'exit':r.get('exit'),'timed_out':r.get('timed_out')} for r in records]),flush=True)
        if not build_failure:
            builds = [r for r in records if r['command'][1:3] == ['test','-c']]
            self.assertTrue(builds)
            self.assertTrue(all(r.get('exit') == 0 and not r.get('timed_out') for r in builds))
            runs = [r for r in records if r['command'][0].endswith('.test')]
            self.assertTrue(runs)
            codes = {'exit2':2, 'panic':2, 'goroutine-panic':2, 'timeout':2, 'signal':-9,
                     'hang':-9, 'skip-all':0, 'no-tests':0, 'skip':0, 'assert':1, 'assert0':0,
                     'fatal':1, 'goroutine-assert':1, 'init0':0, 'init1':1, 'race0':0, 'exit0':0}
            self.assertTrue(all(r['exit'] == codes.get(mode,int(known)) for r in runs))
            self.assertEqual(any(r['timed_out'] for r in runs),mode == 'hang')
            if mode in ['panic','goroutine-panic','assert0','trailing-output']:
                marker = {'panic':'panic: unrelated post-test process panic',
                          'goroutine-panic':'panic: unrelated background panic',
                          'assert0':'real failed assertion', 'trailing-output':'unrelated cleanup error'}[mode]
                self.assertIn(marker,(out/'probe-hysteria-binary.log').read_text())
        self.assertFalse((out/'stale-executed').exists())
        return out,records

    def test_real_controls(self):
        for known in [False,True]:
            with self.subTest(known=known): self.probe(known,'control',reject=False,all_packages=True)

    def test_real_all_review_bypass_classes_both_outcomes(self):
        for known in [False,True]:
            modes = ['exit2','panic','goroutine-panic','trailing-output','hang','timeout','signal',
                     'skip-all','no-tests','skip','assert','assert0','fatal','goroutine-assert','init0','init1']
            if known: modes.append('exit0')
            for mode in modes:
                with self.subTest(known=known,mode=mode): self.probe(known,mode)

    def test_real_data_race_even_with_suppressed_exit(self):
        for known in [False,True]:
            with self.subTest(known=known):
                out,_ = self.probe(known,'race0',flags=['-race'])
                self.assertIn('WARNING: DATA RACE',(out/'probe-hysteria-binary.log').read_text())

    def test_real_go_normalization_and_dr2_failed_assertion(self):
        for known,mode in [(False,'assert0'),(True,'exit2')]:
            with self.subTest(known=known):
                out,records = self.probe(known,mode,all_packages=True)
                self.assertEqual([r['exit'] for r in records if r['command'][0].endswith('.test')],
                                 [2 if known else 0]*3)
                log=out/'normalized.jsonl'
                env=dict(self.env,SEC_MATRIX_EXPECTED='xfail' if known else 'pass',SEC_MATRIX_PROBE=mode)
                linker=['-ldflags=-linkmode=external'] if sys.platform=='darwin' else []
                record=MATRIX.capture_command([self.go,'test',*linker,'-json','-count=1','-timeout=2s','./...'],
                                              log,self.root,env,records,60)
                self.assertEqual(record['exit'],int(known))
                self.assertNotIn('exit status 2',log.read_text())
                events=[json.loads(l) for l in log.read_text().splitlines()]
                self.assertEqual(sum(e['Action']=='fail' and '/size=' in e.get('Test','') for e in events),18)
                if not known:
                    self.assertEqual(sum(e['Action']=='pass' and 'Test' not in e for e in events),3)

    def test_real_converter_failures_both_outcomes(self):
        real_go=MATRIX.shutil.which(self.go)
        for known in [False,True]:
            for mode,body in [('error','print("converter failed"); sys.exit(2)'),
                              ('empty','sys.exit(0)'),('partial','print("{broken"); sys.exit(0)')]:
                wrapper=self.root/f'converter-{known}-{mode}'
                wrapper.write_text(f'#!{sys.executable}\nimport os, sys\n'
                                   f'if sys.argv[1:3] == ["tool","test2json"]:\n    {body}\n'
                                   f'os.execv({real_go!r},[{real_go!r}]+sys.argv[1:])\n')
                wrapper.chmod(0o700)
                with self.subTest(known=known,mode=mode): self.probe(known,'control',go=str(wrapper))

    def test_real_build_failure_and_stale_binary_both_outcomes(self):
        for known in [False,True]:
            path=self.root/'hysteria/broken_test.go'
            path.write_text('package probe\nthis does not compile\n')
            try:
                with self.subTest(known=known): self.probe(known,'control',stale=True,build_failure=True)
            finally:
                path.unlink()
        # A compiler returning success without writing output cannot reuse an
        # existing binary or bypass execution.
        wrapper=self.root/'compiler-no-output'
        wrapper.write_text(f'#!{sys.executable}\nimport os,sys\n'
                           'if sys.argv[1:3] == ["test","-c"]: sys.exit(0)\n'
                           f'os.execv({MATRIX.shutil.which(self.go)!r},[{MATRIX.shutil.which(self.go)!r}]+sys.argv[1:])\n')
        wrapper.chmod(0o700)
        for known in [False,True]:
            with self.subTest(known=known): self.probe(known,'control',go=str(wrapper),stale=True,build_failure=True)


if __name__=='__main__':
    unittest.main()
