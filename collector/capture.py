#!/usr/bin/env python3
"""Independent page collector. CANDIDATE FOR REVIEW ONLY. Written by Duet (the builder),
Nov 10 2026. Never run against a live page; never run on GitHub.

Runs ONLY inside the `capture` job of .github/workflows/collect.yml. That job has no
secrets, no OIDC token and read-only repo access. The page is untrusted input.

What it observes: Playwright WebKit with "iPhone 13" emulation (screen size, user agent,
touch). It is NOT iOS Safari and NOT an iPhone. It can't prove sound, real touch, autoplay
rules or anything an iPhone does differently.

What it decides: per tap target, whether the element is the top thing at its own center
(document.elementFromPoint), the same logic as v3 tools/capture_page.py. It decides nothing
else; the Vault checker makes the case decision.

Writes into --out:
  pre-screenshot.png, pre-page_capture.json, pre-hit_test.json   (v3 evidence format)
  run.json   job, url, nonce, run id, commit, one capture time
All of --out is attested by the next job. Inputs come from env (IN_*), never from the shell line.
"""
import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys

DEVICE = "iPhone 13"
COLLECTOR = "gh-collector"
CONTROL_PREFIX = "http://127.0.0.1:8765/"
JOB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d([+-]\d\d:\d\d|Z)$")
SAFE_FIELD = re.compile(r"^[A-Za-z0-9 ._:/@#-]{1,200}$")

HIT_JS = """
(sel) => {
  const el = document.querySelector(sel);
  if (!el) return {found:false};
  el.scrollIntoView({block:'center', inline:'center'});
  const r = el.getBoundingClientRect();
  const x = r.left + r.width/2, y = r.top + r.height/2;
  const inView = x >= 0 && y >= 0 && x <= innerWidth && y <= innerHeight && r.width > 0 && r.height > 0;
  const hit = document.elementFromPoint(x, y);
  const ok = !!hit && (hit === el || el.contains(hit));
  const desc = (n) => n ? (n.tagName.toLowerCase() + (n.id ? '#' + n.id : '') +
     (n.className && typeof n.className === 'string' ? '.' + n.className.trim().split(/\\s+/).slice(0,3).join('.') : '')) : null;
  return {found:true, in_view:inView, center:[Math.round(x), Math.round(y)],
          hit_is_target: ok && inView, covered_by: ok ? null : desc(hit)};
}
"""


class InputError(ValueError):
    pass


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def read_inputs(env):
    """Validates every dispatch input. Anything odd stops the run before a page opens."""
    g = {k: env.get(k, "") for k in ("IN_JOB_ID", "IN_URL", "IN_NONCE", "IN_TARGETS", "IN_CS",
                                      "IN_CI", "IN_CV", "IN_CVT")}
    if not JOB_RE.match(g["IN_JOB_ID"]):
        raise InputError("job_id")
    url = g["IN_URL"]
    if not (url.startswith("https://") or url.startswith(CONTROL_PREFIX)) or any(c.isspace() for c in url) or len(url) > 2000:
        raise InputError("url")
    if not NONCE_RE.match(g["IN_NONCE"]):
        raise InputError("nonce")
    try:
        targets = json.loads(g["IN_TARGETS"])
    except ValueError:
        raise InputError("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 20:
        raise InputError("targets")
    parsed = []
    for t in targets:
        if not isinstance(t, str) or "=" not in t or len(t) > 300:
            raise InputError("targets")
        name, _, sel = t.partition("=")
        if not name.strip() or not sel.strip():
            raise InputError("targets")
        parsed.append((name.strip(), sel.strip()))
    for k in ("IN_CS", "IN_CI", "IN_CV"):
        if not SAFE_FIELD.match(g[k]):
            raise InputError(k)
    if not TIME_RE.match(g["IN_CVT"]):
        raise InputError("content_version_time")
    return {"job_id": g["IN_JOB_ID"], "url": url, "nonce": g["IN_NONCE"], "targets": parsed,
            "content_ref": {"system": g["IN_CS"], "id": g["IN_CI"], "version": g["IN_CV"],
                            "version_time": g["IN_CVT"]}}


def run_identity(env):
    """The workflow run this capture belongs to, from GitHub's own runner variables."""
    rid, att, src, repo = (env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""),
                           env.get("GITHUB_SHA", ""), env.get("GITHUB_REPOSITORY", ""))
    if not rid.isdigit() or not att.isdigit() or not SHA_RE.match(src) or "/" not in repo:
        raise InputError("not inside a GitHub Actions run")
    return {"run_id": rid, "run_attempt": att, "source_sha": src, "repo": repo}


def build_records(inp, ident, captured_at, env_desc, shot_name, shot_sha, target_results):
    common = {"job_id": inp["job_id"], "collector": COLLECTOR, "phase": "pre", "url": inp["url"],
              "content_ref": inp["content_ref"], "environment": env_desc, "captured_at": captured_at}
    cap = dict(common, kind="page_capture", artifacts=[{"file": shot_name, "sha256": shot_sha}])
    hit = dict(common, kind="hit_test", targets=target_results)
    run = {"job_id": inp["job_id"], "url": inp["url"], "nonce": inp["nonce"], "run_id": ident["run_id"],
           "run_attempt": ident["run_attempt"], "source_sha": ident["source_sha"], "repo": ident["repo"],
           "captured_at": captured_at, "collector": COLLECTOR}
    return cap, hit, run


def capture(inp, ident, out):  # pragma: no cover - needs Playwright and a real page (UNRUN)
    from playwright.sync_api import sync_playwright
    os.makedirs(out, exist_ok=True)
    with sync_playwright() as p:
        dev = p.devices[DEVICE]
        browser = p.webkit.launch()
        ctx = browser.new_context(**dev)
        page = ctx.new_page()
        page.goto(inp["url"], wait_until="networkidle", timeout=60000)
        captured_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        env_desc = {"profile": "customer", "logged_in": False, "cookies_preset": False, "fresh_context": True,
                    "test_device": False, "engine": "playwright-webkit (emulated, NOT a real iPhone)",
                    "device_emulated": DEVICE, "viewport": dev["viewport"], "user_agent": dev["user_agent"]}
        shot = "pre-screenshot.png"
        page.screenshot(path=os.path.join(out, shot), full_page=False)
        results = []
        for name, sel in inp["targets"]:
            r = page.evaluate(HIT_JS, sel)
            r.update({"name": name, "selector": sel})
            results.append(r)
        browser.close()
    cap, hit, run = build_records(inp, ident, captured_at, env_desc, shot, sha(os.path.join(out, shot)), results)
    for fn, obj in (("pre-page_capture.json", cap), ("pre-hit_test.json", hit), ("run.json", run)):
        with open(os.path.join(out, fn), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, sort_keys=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        inp = read_inputs(os.environ)
        ident = run_identity(os.environ)
    except InputError as e:
        print(f"REFUSED: bad input ({e})", file=sys.stderr)
        return 2
    capture(inp, ident, a.out)
    print("wrote evidence to", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
