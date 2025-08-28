"""
Warnetix demo seed — nyalain traffic event buat presentasi/dashboard.

FITUR:
- Multi-device (Windows/Mac/Linux/Android/iOS) dengan rotasi otomatis
- Severity berbobot (low/medium/high/critical) + kategori umum
- Nama file & ekstensi sesuai kategori (pdf/docx/exe/js/zip/…)
- Auto-bikin file dummy di ./uploads agar path valid
- Rate limiter + jitter (+ burst awal biar grafik langsung hidup)
- OPSIONAL: kirim juga ke /scan-file (butuh 'requests') untuk munculin event hasil scan

USAGE (PowerShell, venv aktif):
  python utils/demo_seed.py               # default: 120 event @ 5 eps
  python utils/demo_seed.py --count 400 --rate 20
  python utils/demo_seed.py --duration 60 --rate 8
  python utils/demo_seed.py --scan-share 0.15     # 15% event ikut upload /scan-file
  python utils/demo_seed.py --devices "dev-xav:XavPC:Windows,lab-01:LabPC:Windows,mac-01:Mac:macOS"

ENV:
  API=http://127.0.0.1:8000   (default)
"""

from __future__ import annotations
import os, sys, time, json, random, string, argparse, pathlib, tempfile

API = os.environ.get("API", "http://127.0.0.1:8000")

# ---- optional requests (disarankan) ----
try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

# ---------- katalog kategori → ekstensi + generator nama ----------
CAT_EXT = {
    "document": ["pdf", "docx", "doc", "xlsx", "pptx", "txt"],
    "image":    ["jpg", "png", "gif", "svg", "bmp"],
    "archive":  ["zip", "7z", "rar", "tar", "gz"],
    "executable":["exe", "dll", "msi", "bin", "sh"],
    "script":   ["js", "ps1", "vbs", "py", "bat"],
    "macro":    ["docm", "xlsm"],
    "pdf_js":   ["pdf"],
    "installer":["exe", "msi", "pkg", "dmg"],
    "email":    ["eml", "msg"],
    "other":    ["dat", "bin", "iso"],
}

DEFAULT_CATEGORIES = list(CAT_EXT.keys())

WORDS = [
    "invoice","report","setup","payload","backup","project","q4","draft",
    "driver","update","resume","payment","id","credential","statement",
    "scan","photo","archive","backup","client","internal","confidential",
]

def rand_word():
    return random.choice(WORDS)

def rand_filename(cat: str) -> str:
    base = f"{rand_word()}_{random.randint(1000,9999)}"
    ext = random.choice(CAT_EXT.get(cat, ["bin"]))
    # sedikit variasi nama
    if cat in ("executable","installer") and random.random() < 0.4:
        base = base.replace("setup","setup_pro").replace("driver","driver_update")
    if cat == "archive" and random.random() < 0.3:
        base = "backup_" + base
    return f"{base}.{ext}"

# ---------- devices ----------
DEFAULT_DEVICES = [
    ("dev-xav","XavPC","Windows"),
    ("lab-01","LabPC","Windows"),
    ("mac-01","MacBook","macOS"),
    ("lin-01","SrvA","Linux"),
    ("and-01","Pixel","Android"),
]

# ---------- distribusi severity ----------
def choose_severity(p_crit=0.05, p_high=0.15, p_med=0.30):
    r = random.random()
    if r < p_crit: return "critical"
    r -= p_crit
    if r < p_high: return "high"
    r -= p_high
    if r < p_med: return "medium"
    return "low"

# ---------- http helpers ----------
def post_json(url: str, payload: dict) -> tuple[int,str]:
    if requests:
        try:
            res = requests.post(url, json=payload, timeout=5)
            return res.status_code, res.text
        except Exception as e:
            return 0, str(e)
    # fallback urllib (tanpa dependency)
    import urllib.request
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:  # nosec - demo
            return r.getcode(), r.read().decode("utf-8", "ignore")
    except Exception as e:  # pragma: no cover
        return 0, str(e)

def post_files(url: str, files: list[tuple[str, tuple[str, bytes, str]]]) -> tuple[int,str]:
    if not requests:
        return 0, "requests not installed (scan-file disabled)"
    try:
        res = requests.post(url, files=files, timeout=10)
        return res.status_code, res.text
    except Exception as e:
        return 0, str(e)

# ---------- file helpers ----------
UPLOADS = pathlib.Path("uploads")
UPLOADS.mkdir(parents=True, exist_ok=True)

def ensure_dummy_file(path: pathlib.Path, size: int = 4096) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with open(path, "wb") as f:
            f.write(os.urandom(min(size, 128*1024)))  # cap 128KB

# ---------- seeding ----------
def seed_once(api: str, devices, categories, p_crit, p_high, p_med, scan_share: float, verbose=False) -> dict:
    dev = random.choice(devices)
    cat = random.choice(categories)
    sev = choose_severity(p_crit, p_high, p_med)
    fname = rand_filename(cat)
    rel_path = pathlib.Path("uploads") / fname
    ensure_dummy_file(rel_path)

    payload = {
        "path": str(rel_path),
        "meta": {"reason":"demo_seed", "category": cat},
        "result": {"name": fname},
        "severity": sev,
        "category": cat,
        "agent": {"id": dev[0], "hostname": dev[1], "os": dev[2]},
        "enqueue_deep_scan": False
    }

    code, text = post_json(f"{api}/events/push", payload)
    ok = (200 <= code < 300)

    if verbose:
        print(f"[push] {code} {fname} sev={sev} cat={cat} dev={dev[0]}")

    # optional: kirim juga ke /scan-file (multipart)
    uploaded = False
    if ok and scan_share > 0 and random.random() < scan_share and requests:
        try:
            with open(rel_path, "rb") as fh:
                files = [("files", (fname, fh.read(), "application/octet-stream"))]
            c2, t2 = post_files(f"{api}/scan-file", files)
            uploaded = (200 <= c2 < 300)
            if verbose:
                print(f"[scan-file] {c2} {fname}")
        except Exception as e:
            if verbose:
                print(f"[scan-file] error {e}")

    return {"ok": ok, "uploaded": uploaded, "sev": sev, "cat": cat, "dev": dev[0], "code": code}

def main():
    ap = argparse.ArgumentParser(description="Warnetix demo seeder")
    ap.add_argument("--api", default=API, help="API base, default %(default)s")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--count", type=int, default=120, help="total events (default %(default)s)")
    grp.add_argument("--duration", type=int, help="durasi detik (override count)")
    ap.add_argument("--rate", type=float, default=5.0, help="events per second (default %(default)s)")
    ap.add_argument("--burst", type=int, default=10, help="burst awal (default %(default)s)")
    ap.add_argument("--jitter", type=float, default=0.25, help="jitter 0..1 (default %(default)s)")
    ap.add_argument("--scan-share", type=float, default=0.0, help="probabilitas ikut /scan-file (0..1)")
    ap.add_argument("--devices", default="", help='format: "id:host:os,id2:host2:os2" (default built-in)')
    ap.add_argument("--categories", default=",".join(DEFAULT_CATEGORIES), help="daftar kategori dipakai")
    ap.add_argument("--crit", type=float, default=0.05, help="prob critical")
    ap.add_argument("--high", type=float, default=0.15, help="prob high")
    ap.add_argument("--med", type=float, default=0.30, help="prob medium")
    ap.add_argument("--seed", type=int, default=None, help="random seed")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # devices
    devices = DEFAULT_DEVICES[:]
    if args.devices.strip():
        devices = []
        for part in args.devices.split(","):
            try:
                i,h,o = part.strip().split(":")
                devices.append((i,h,o))
            except ValueError:
                print(f"skip device format: {part}")

    # categories
    cats = [c.strip() for c in args.categories.split(",") if c.strip()]

    # warm burst
    print(f"[info] API={args.api} | rate={args.rate}/s | burst={args.burst} | scan-share={args.scan_share}")
    print(f"[info] devices={len(devices)} | categories={cats}")
    print("[info] burst…")
    ok=err=up=0
    for _ in range(max(0,args.burst)):
        r = seed_once(args.api, devices, cats, args.crit, args.high, args.med, args.scan_share, args.verbose)
        ok += 1 if r["ok"] else 0
        err += 1 if not r["ok"] else 0
        up  += 1 if r["uploaded"] else 0
        time.sleep(0.02)

    # main loop
    start = time.time()
    sent = 0
    if args.duration:
        end = start + args.duration
        while time.time() < end:
            r = seed_once(args.api, devices, cats, args.crit, args.high, args.med, args.scan_share, args.verbose)
            ok += 1 if r["ok"] else 0
            err += 1 if not r["ok"] else 0
            up  += 1 if r["uploaded"] else 0
            sent += 1
            # rate control + jitter
            base_sleep = (1.0 / max(args.rate, 0.01))
            jitter = base_sleep * (random.random() - 0.5) * 2 * args.jitter
            time.sleep(max(0.0, base_sleep + jitter))
    else:
        total = args.count
        for _ in range(total):
            r = seed_once(args.api, devices, cats, args.crit, args.high, args.med, args.scan_share, args.verbose)
            ok += 1 if r["ok"] else 0
            err += 1 if not r["ok"] else 0
            up  += 1 if r["uploaded"] else 0
            sent += 1
            base_sleep = (1.0 / max(args.rate, 0.01))
            jitter = base_sleep * (random.random() - 0.5) * 2 * args.jitter
            time.sleep(max(0.0, base_sleep + jitter))

    dur = time.time() - start
    print(f"[done] sent={sent+args.burst} ok={ok} err={err} uploaded(/scan-file)={up} in {dur:.1f}s "
          f"({(sent+args.burst)/max(dur,1e-6):.1f} eps)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[abort] Ctrl+C")
