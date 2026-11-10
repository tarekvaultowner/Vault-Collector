#!/usr/bin/env python3
"""Independent page collector. CANDIDATE 5 FOR REVIEW ONLY (offline; the browser path is UNRUN). Written by Duet
(the builder), Nov 10 2026. Candidate 3 of this file ran on GitHub (merged 716b11ca); candidates 4 and 5 have not.

Candidate 5 (plan c4851d28 Part B, checker 9k/9l P-2 and P-1 validators): two SEPARATE observations.
  ENTRY (P-2): the main-document response of the approved page, from Playwright's own navigation objects:
    status and final URL of the response page.goto returned (the first non-redirect response), every redirect hop
    oldest first (url and status, walking request.redirected_from), and the raw body bytes (response.body()),
    written byte-for-byte to <phase>-body.html. page_capture.document_sha256 is the sha256 of THOSE bytes. The body is
    not listed as an artifact (the checker binds it through the signed digest; 9l review).
  OUTCOME (P-1): for each requested step, in order: target_check (the same tap test as HIT_JS), then a real tap of that
    target (Locator.tap, touch context), then navigation (page.url once the navigation the tap started has finished).
    An event is written only for what actually happened: a covered or missing target gets no tap; a tap that fails or
    times out gets no tap event; a tap with no navigation gets no navigation event. The page reached after the tap is
    never hashed and never compared with the entry page.
The collector judges nothing; it does not know the approved digest or the approved next URL.
Safety: service workers are blocked (so the main-document response is the network one) and every request whose method
is not GET or HEAD is aborted. That is a method filter ONLY (collector c6 correction, Codex 19:43Z): a GET form, a GET
link with side effects or anything a page does without a request is NOT prevented, so this collector must only be
pointed at pages known to be harmless (the localhost control pages, or an approved read-only page).
Pinned API facts were read from playwright-python v1.47.0
playwright/sync_api/_generated.py (sha256 7faf96e2...): Page.goto, Page.expect_navigation, Page.url, Locator.tap
(needs has_touch), Response.status/url/body/request, Request.redirected_from/response/method, Route.abort/continue_,
Browser.new_context(service_workers=...). None of this was executed against a real browser here.

Candidate 4 change (screenshot timing, found in the Nov 10 live review): candidate 3 took its
only screenshot BEFORE the tap test scrolled each target into view, so the picture need not show
the measured target. Now each tap test is followed at once by a screenshot of that same scrolled
state (pre-target-NN.png), listed as artifacts on the hit_test record, so the attest job covers
them. Smooth scrolling is turned off first (CSS scroll-behavior set to 'auto' on html and body;
no layout change) so the picture can't catch a scroll mid-way.
The first full-page picture (pre-screenshot.png) is unchanged.

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
PHASES = ("pre", "post")  # candidate 5
NAV_TIMEOUT_MS = 15000  # candidate 5: how long a tap may take to start and finish its navigation
STEP_EVENTS = ("target_check", "tap", "navigation")  # candidate 5: the order the checker requires
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
  // Candidate 4: turn off smooth scrolling (CSS scroll-behavior only, no layout change) so the
  // picture taken right after this test shows the settled position.
  document.documentElement.style.scrollBehavior = 'auto';
  if (document.body) document.body.style.scrollBehavior = 'auto';
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


class CollectorError(RuntimeError):  # candidate 5: an observation that can't be recorded honestly; nothing is written
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
                                      "IN_CI", "IN_CV", "IN_CVT", "IN_PHASE", "IN_STEPS")}
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
    names = [n for n, _ in parsed]
    if len(set(names)) != len(names):
        raise InputError("targets")  # candidate 5: one selector per name
    phase = g["IN_PHASE"] or "pre"  # candidate 5: absent means pre, as in candidates 3-4
    if phase not in PHASES:
        raise InputError("phase")
    steps = []
    if g["IN_STEPS"]:
        try:
            raw = json.loads(g["IN_STEPS"])
        except ValueError:
            raise InputError("steps")
        if not isinstance(raw, list) or not 1 <= len(raw) <= 10:
            raise InputError("steps")
        for i, st in enumerate(raw, start=1):
            if not isinstance(st, dict) or set(st) != {"step", "target"} or st["step"] != i \
                    or isinstance(st["step"], bool) or st["target"] not in names:
                raise InputError("steps")
            steps.append({"step": i, "target": st["target"]})
    return {"job_id": g["IN_JOB_ID"], "url": url, "nonce": g["IN_NONCE"], "targets": parsed,
            "content_ref": {"system": g["IN_CS"], "id": g["IN_CI"], "version": g["IN_CV"],
                            "version_time": g["IN_CVT"]},
            "phase": phase, "steps": steps}


def run_identity(env):
    """The workflow run this capture belongs to, from GitHub's own runner variables."""
    rid, att, src, repo = (env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""),
                           env.get("GITHUB_SHA", ""), env.get("GITHUB_REPOSITORY", ""))
    if not rid.isdigit() or not att.isdigit() or not SHA_RE.match(src) or "/" not in repo:
        raise InputError("not inside a GitHub Actions run")
    return {"run_id": rid, "run_attempt": att, "source_sha": src, "repo": repo}


def build_records(inp, ident, captured_at, env_desc, shot_name, shot_sha, target_results, target_shots=None,
                  entry=None, events=None):
    """target_shots: [{"file", "sha256"}] taken right after each tap test (candidate 4).
    entry (candidate 5): {"status", "final_url", "redirects", "body_file", "document_sha256"} from observe_entry.
    events (candidate 5): the ordered interaction events from run_steps; None means no interaction was requested."""
    common = {"job_id": inp["job_id"], "collector": COLLECTOR, "phase": inp.get("phase", "pre"), "url": inp["url"],
              "content_ref": inp["content_ref"], "environment": env_desc, "captured_at": captured_at}
    cap = dict(common, kind="page_capture", artifacts=[{"file": shot_name, "sha256": shot_sha}])
    if entry is not None:  # candidate 5 (P-2)
        cap["response"] = {k: entry[k] for k in ("status", "final_url", "redirects", "body_file")}
        cap["document_sha256"] = entry["document_sha256"]
    hit = dict(common, kind="hit_test", targets=target_results)
    if target_shots:
        hit["artifacts"] = list(target_shots)
    inter = dict(common, kind="interaction", events=list(events)) if events is not None else None  # candidate 5
    run = {"job_id": inp["job_id"], "url": inp["url"], "nonce": inp["nonce"], "run_id": ident["run_id"],
           "run_attempt": ident["run_attempt"], "source_sha": ident["source_sha"], "repo": ident["repo"],
           "captured_at": captured_at, "collector": COLLECTOR}
    if inter is not None:
        return cap, hit, run, inter  # candidate 5
    return cap, hit, run


# --- candidate 5: pure observation helpers. They take Playwright objects (or test doubles) and never judge. ---
def redirect_hops(response):
    """Every redirect hop before the final response, oldest first: [{"url", "status"}]. A hop whose response was not
    received cannot be described honestly, so the whole observation is refused."""
    hops, req = [], response.request
    while req.redirected_from is not None:
        prev = req.redirected_from
        r = prev.response()
        if r is None:
            raise CollectorError("a redirect hop has no response")
        hops.append({"url": prev.url, "status": r.status})
        req = prev
    hops.reverse()
    return hops


def observe_entry(page, url, out, phase):
    """P-2: navigate to the approved URL once and record the main-document response. Writes <phase>-body.html."""
    resp = page.goto(url, wait_until="networkidle", timeout=60000)
    if resp is None:
        raise CollectorError("the navigation returned no main-document response")
    body = resp.body()
    if not isinstance(body, (bytes, bytearray)):
        raise CollectorError("the main-document body is not bytes")
    name = f"{phase}-body.html"
    with open(os.path.join(out, name), "wb") as f:
        f.write(bytes(body))
    return {"status": resp.status, "final_url": resp.url, "redirects": redirect_hops(resp), "body_file": name,
            "document_sha256": hashlib.sha256(bytes(body)).hexdigest()}


def run_steps(page, inp, timeout_ms=NAV_TIMEOUT_MS):
    """P-1: for each step in order: target_check, then tap (only if the target is found, in view, the top element and
    uncovered), then navigation (only if the tap's navigation finished). Stops at the first step that can't go on."""
    sel = dict(inp["targets"])
    events = []
    for st in inp["steps"]:
        name = st["target"]
        r = page.evaluate(HIT_JS, sel[name])
        tc = {"step": st["step"], "type": "target_check", "target": name, "selector": sel[name],
              "found": r.get("found") is True, "in_view": r.get("in_view") is True,
              "hit_is_target": r.get("hit_is_target") is True,
              "covered_by": r.get("covered_by") if isinstance(r.get("covered_by"), str) else None}
        events.append(tc)
        if not (tc["found"] and tc["in_view"] and tc["hit_is_target"] and tc["covered_by"] is None):
            break
        try:
            with page.expect_navigation(wait_until="load", timeout=timeout_ms):
                page.locator(sel[name]).tap(timeout=timeout_ms)
                events.append({"step": st["step"], "type": "tap", "target": name, "selector": sel[name]})
        except Exception:  # noqa: BLE001  Playwright raises TimeoutError/Error. If the tap itself failed there is no
            break           # tap event; if it tapped but no navigation finished there is no navigation event.
        events.append({"step": st["step"], "type": "navigation", "final_url": page.url})
    return events


def _only_get(route):
    """Aborts every request whose method is not GET or HEAD. A method filter only: it does not make GET forms or
    GET side effects safe (collector c6 correction)."""
    if route.request.method in ("GET", "HEAD"):
        route.continue_()
    else:
        route.abort()


def session(page, inp, out, now):
    """One capture on an open page: entry observation, full picture, tap tests with pictures, then the steps."""
    phase = inp["phase"]
    entry = observe_entry(page, inp["url"], out, phase)
    captured_at = now()
    shot = f"{phase}-screenshot.png"
    page.screenshot(path=os.path.join(out, shot), full_page=False)
    results, target_shots = [], []
    for i, (name, sel) in enumerate(inp["targets"], start=1):
        r = page.evaluate(HIT_JS, sel)
        r.update({"name": name, "selector": sel})
        results.append(r)
        tshot = f"{phase}-target-{i:02d}.png"  # candidate 4: picture the exact scrolled state just measured
        page.screenshot(path=os.path.join(out, tshot), full_page=False)
        target_shots.append({"file": tshot, "sha256": sha(os.path.join(out, tshot))})
    events = run_steps(page, inp) if inp["steps"] else None
    return captured_at, entry, shot, results, target_shots, events


def write_records(inp, ident, out, env_desc, captured_at, entry, shot, results, target_shots, events):
    recs = build_records(inp, ident, captured_at, env_desc, shot, sha(os.path.join(out, shot)), results,
                         target_shots, entry=entry, events=events)
    phase = inp["phase"]
    names = [f"{phase}-page_capture.json", f"{phase}-hit_test.json", "run.json", f"{phase}-interaction.json"]
    for fn, obj in zip(names, recs):
        with open(os.path.join(out, fn), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, sort_keys=True)


def capture(inp, ident, out):  # pragma: no cover - needs Playwright and a real page (UNRUN)
    from playwright.sync_api import sync_playwright
    os.makedirs(out, exist_ok=True)
    with sync_playwright() as p:
        dev = p.devices[DEVICE]
        if dev.get("has_touch") is not True:  # Locator.tap requires a touch context
            raise CollectorError("the device profile has no touch")
        browser = p.webkit.launch()
        try:
            ctx = browser.new_context(**dev, service_workers="block")
            ctx.route("**/*", _only_get)
            page = ctx.new_page()
            env_desc = {"profile": "customer", "logged_in": False, "cookies_preset": False, "fresh_context": True,
                        "test_device": False, "engine": "playwright-webkit (emulated, NOT a real iPhone)",
                        "device_emulated": DEVICE, "viewport": dev["viewport"], "user_agent": dev["user_agent"]}
            now = lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")  # noqa: E731
            got = session(page, inp, out, now)
        finally:
            browser.close()
    write_records(inp, ident, out, env_desc, *got)


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
    try:
        capture(inp, ident, a.out)
    except CollectorError as e:  # candidate 5: refuse rather than write a record that claims an observation
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3
    print("wrote evidence to", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
