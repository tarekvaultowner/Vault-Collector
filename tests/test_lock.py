#!/usr/bin/env python3
"""Offline checks of the collector's dependency lock and workflow install step (candidate 2).
Uses the PyPI metadata snapshot saved in collector/deps-metadata.json. Installs nothing.
  python3 tests/test_lock.py [path/to/collector-repo]
"""
import json, os, re, sys
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ = os.path.join(ROOT, "collector", "requirements.txt")
META = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "collector", "deps-metadata.json")
WF = os.path.join(ROOT, ".github", "workflows", "collect.yml")

def norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()

def parse_lock(path):
    text = re.sub(r"\\\n", " ", open(path).read())
    pins = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip() if not line.strip().startswith("--hash") else line.strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)==([^\s]+)(.*)$", line)
        if not m:
            continue
        pins[norm(m.group(1))] = (m.group(2), set(re.findall(r"--hash=sha256:([0-9a-f]{64})", m.group(3))))
    return pins

def main():
    meta = json.load(open(META))["packages"]
    pins = parse_lock(REQ)
    results = []
    def rec(name, ok, detail=""):
        results.append((ok, name, detail))
    for name, (ver, hashes) in pins.items():
        rec(f"{name}=={ver} has hashes", bool(hashes))
    for pname, info in meta.items():
        n = norm(pname)
        got = pins.get(n)
        rec(f"{n} is in the lock at {info['version']}", bool(got) and got[0] == info["version"], str(got and got[0]))
        if got:
            rec(f"{n} hashes match PyPI's files exactly", got[1] == set(info["files"].values()))
        for dep in info.get("requires_dist") or []:
            if "extra ==" in dep:
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\(?\s*==\s*([^\s;)]+)\)?)?", dep)
            dn, dv = norm(m.group(1)), m.group(2)
            ok = dn in pins and (dv is None or pins[dn][0] == dv)
            rec(f"{n} needs {dn}{'==' + dv if dv else ''}: locked", ok, str(pins.get(dn, ('missing',))[0]))
    files = {f for i in meta.values() for f in i["files"]}
    rec("lock covers a Linux x86_64 wheel for playwright", any("manylinux1_x86_64" in f and f.startswith("playwright") for f in files))
    rec("lock covers a cp312 Linux x86_64 wheel for greenlet", any(f.startswith("greenlet-3.0.3-cp312") and "x86_64" in f and "musllinux" not in f for f in files))
    wf = open(WF).read()
    rec("workflow installs with --require-hashes --no-deps from the lock", "--require-hashes --no-deps -r collector/requirements.txt" in wf)
    rec("workflow runs pip check after install", "python -m pip check" in wf)
    rec("workflow import-checks greenlet, pyee and the sync API", "import greenlet, pyee, typing_extensions, playwright.sync_api" in wf)
    bad = [r for r in results if not r[0]]
    for ok, name, detail in results:
        print(("ok  " if ok else "BAD ") + name + ("" if ok else f"  ({detail})"))
    print(f"\n{len(results) - len(bad)} of {len(results)} lock checks passed (offline, nothing installed).")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
