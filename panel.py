#!/usr/bin/env python3
"""
Panel perso pour héberger et gérer un bot (ici StickersClonerBot).

Fonctions : démarrer / arrêter / redémarrer le bot (relance auto en cas de
crash), logs en direct, gestionnaire de fichiers (voir, éditer, importer,
télécharger), terminal de commandes, sauvegarde / restauration des bases JSON.

Installation :   pip install flask psutil
Lancement    :   PANEL_PASSWORD="ton-mot-de-passe" python3 panel.py

Variables d'environnement (toutes facultatives) :
  PANEL_PASSWORD   mot de passe du panel (sinon généré et écrit dans .panel_password)
  PORT / PANEL_PORT port d'écoute (défaut 8080)
  BOT_DIR          dossier du bot (défaut : le dossier de panel.py)
  BOT_CMD          commande de lancement (défaut : python3 -u bot.py)
  PANEL_AUTOSTART  1 = démarre le bot avec le panel (défaut), 0 = non
"""
import atexit
import collections
import hmac
import io
import logging
import os
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request, send_file, session

try:
    import psutil
except ImportError:  # le panel marche sans, mais sans les stats CPU/RAM
    psutil = None

HERE = Path(__file__).resolve().parent
BOT_DIR = Path(os.environ.get("BOT_DIR", HERE)).resolve()
BOT_CMD = os.environ.get("BOT_CMD") or f"{shlex.quote(sys.executable)} -u bot.py"
PORT = int(os.environ.get("PORT") or os.environ.get("PANEL_PORT") or 8080)
AUTOSTART = os.environ.get("PANEL_AUTOSTART", "1") != "0"
LOG_FILE = HERE / "bot.log"
LOG_MAX_BYTES = 2 * 1024 * 1024
BACKUP_PATTERNS = (".json", ".env")
BACKUP_NAMES = {"token.txt"}
MAX_EDIT_BYTES = 1024 * 1024


# --------------------------------------------------------------------------
# Secrets : mot de passe + clé de session
# --------------------------------------------------------------------------
def _load_password() -> str:
    pw = os.environ.get("PANEL_PASSWORD", "").strip()
    if pw:
        return pw
    f = HERE / ".panel_password"
    if f.is_file():
        pw = f.read_text(encoding="utf-8").strip()
        if pw:
            return pw
    pw = secrets.token_urlsafe(12)
    f.write_text(pw, encoding="utf-8")
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    print(f"\n[panel] Aucun mot de passe défini. Mot de passe généré : {pw}")
    print(f"[panel] (enregistré dans {f} — définis PANEL_PASSWORD pour le changer)\n", flush=True)
    return pw


def _load_secret() -> str:
    env = os.environ.get("PANEL_SECRET")
    if env:
        return env
    f = HERE / ".panel_secret"
    if f.is_file():
        return f.read_text(encoding="utf-8").strip()
    s = secrets.token_hex(32)
    f.write_text(s, encoding="utf-8")
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    return s


PASSWORD = _load_password()
app = Flask(__name__)
app.secret_key = _load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=200 * 1024 * 1024)
logging.getLogger("werkzeug").setLevel(logging.WARNING)


# --------------------------------------------------------------------------
# Superviseur du bot
# --------------------------------------------------------------------------
class BotRunner:
    def __init__(self):
        self.lock = threading.RLock()
        self.proc = None
        self.thread = None
        self.want = False
        self.started_at = None
        self.restarts = 0
        self.last_exit = None
        self.seq = 0
        self.buf = collections.deque(maxlen=3000)
        self._ps = None
        self._logf = None
        self._open_log()

    # -- logs --
    def _open_log(self):
        try:
            if LOG_FILE.is_file() and LOG_FILE.stat().st_size > LOG_MAX_BYTES:
                LOG_FILE.write_text("", encoding="utf-8")
            self._logf = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
        except OSError:
            self._logf = None

    def log(self, line: str):
        line = line.rstrip("\r\n")
        with self.lock:
            self.seq += 1
            self.buf.append((self.seq, line))
            if self._logf:
                try:
                    self._logf.write(line + "\n")
                except OSError:
                    pass

    def lines_after(self, after: int):
        with self.lock:
            return [{"n": n, "t": t} for n, t in self.buf if n > after], self.seq

    # -- cycle de vie --
    def running(self) -> bool:
        p = self.proc
        return p is not None and p.poll() is None

    def start(self):
        with self.lock:
            self.want = True
            if self.thread and self.thread.is_alive():
                return
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def _spawn(self):
        self.log(f"[panel] démarrage : {BOT_CMD}")
        self.proc = subprocess.Popen(
            shlex.split(BOT_CMD), cwd=str(BOT_DIR),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, errors="replace", start_new_session=True,
        )
        self.started_at = time.time()
        self._ps = None
        if psutil:
            try:
                self._ps = psutil.Process(self.proc.pid)
                self._ps.cpu_percent(None)
            except Exception:
                self._ps = None

    def _loop(self):
        fails = 0
        while self.want:
            try:
                self._spawn()
            except Exception as e:
                self.log(f"[panel] impossible de lancer le bot : {e}")
                self.want = False
                break
            for line in self.proc.stdout:
                self.log(line)
            code = self.proc.wait()
            uptime = time.time() - (self.started_at or time.time())
            self.last_exit = code
            if not self.want:
                self.log(f"[panel] bot arrêté (code {code})")
                break
            fails = 0 if uptime > 60 else fails + 1
            delay = min(60, 3 * (2 ** (fails - 1))) if fails else 3
            self.restarts += 1
            self.log(f"[panel] le bot s'est arrêté (code {code}) — relance dans {delay}s")
            for _ in range(int(delay * 10)):
                if not self.want:
                    break
                time.sleep(0.1)
        self.started_at = None

    def stop(self):
        with self.lock:
            self.want = False
            p = self.proc
        if p and p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        t = self.thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=10)

    def restart(self):
        self.stop()
        self.restarts = 0
        self.start()

    def stats(self) -> dict:
        d = {
            "running": self.running(),
            "pid": self.proc.pid if self.running() else None,
            "uptime": int(time.time() - self.started_at) if self.running() and self.started_at else 0,
            "restarts": self.restarts,
            "last_exit": self.last_exit,
            "cpu": None, "ram_mb": None,
            "bot_dir": str(BOT_DIR),
            "has_bot": (BOT_DIR / "bot.py").is_file(),
            "psutil": psutil is not None,
        }
        if d["running"] and self._ps:
            try:
                procs = [self._ps] + self._ps.children(recursive=True)
                d["cpu"] = round(sum(p.cpu_percent(None) for p in procs), 1)
                d["ram_mb"] = round(sum(p.memory_info().rss for p in procs) / 1048576, 1)
            except Exception:
                pass
        return d


bot = BotRunner()


def _shutdown(*_):
    bot.stop()
    sys.exit(0)


atexit.register(bot.stop)
signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
_fails = {}  # ip -> (compteur, début de fenêtre)


def _ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "?"


def _locked(ip: str) -> int:
    n, t0 = _fails.get(ip, (0, 0))
    if n >= 5 and time.time() - t0 < 600:
        return int(600 - (time.time() - t0))
    if time.time() - t0 >= 600:
        _fails.pop(ip, None)
    return 0


@app.before_request
def guard():
    if request.path in ("/", "/login", "/api/login"):
        return None
    if not session.get("ok"):
        return jsonify(error="Session expirée, reconnecte-toi."), 401
    if request.method == "POST" and request.headers.get("X-Panel") != "1":
        return jsonify(error="Requête refusée."), 403
    return None


@app.post("/api/login")
def login():
    ip = _ip()
    wait = _locked(ip)
    if wait:
        return jsonify(error=f"Trop d'essais. Réessaie dans {wait // 60 + 1} min."), 429
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if hmac.compare_digest(pw.encode(), PASSWORD.encode()):
        session["ok"] = True
        session.permanent = True
        _fails.pop(ip, None)
        return jsonify(ok=True)
    n, t0 = _fails.get(ip, (0, time.time()))
    _fails[ip] = (n + 1, t0)
    return jsonify(error="Mot de passe incorrect."), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# Bot
# --------------------------------------------------------------------------
@app.get("/api/status")
def api_status():
    return jsonify(bot.stats())


@app.post("/api/bot/<action>")
def api_bot(action):
    if action == "start":
        if not (BOT_DIR / "bot.py").is_file():
            return jsonify(error="bot.py est introuvable dans le dossier du bot."), 400
        bot.start()
    elif action == "stop":
        bot.stop()
    elif action == "restart":
        bot.restart()
    else:
        abort(404)
    return jsonify(ok=True)


@app.get("/api/logs")
def api_logs():
    after = request.args.get("after", type=int, default=0)
    lines, last = bot.lines_after(after)
    return jsonify(lines=lines, last=last)


# --------------------------------------------------------------------------
# Fichiers
# --------------------------------------------------------------------------
def safe(rel: str) -> Path:
    p = (BOT_DIR / (rel or "").lstrip("/")).resolve()
    if p != BOT_DIR and BOT_DIR not in p.parents:
        abort(400, "Chemin interdit.")
    return p


def rel_of(p: Path) -> str:
    return "" if p == BOT_DIR else str(p.relative_to(BOT_DIR))


@app.get("/api/files")
def api_files():
    d = safe(request.args.get("path", ""))
    if not d.is_dir():
        return jsonify(error="Dossier introuvable."), 404
    items = []
    for e in d.iterdir():
        try:
            st = e.stat()
        except OSError:
            continue
        items.append({"name": e.name, "dir": e.is_dir(), "size": st.st_size, "mtime": int(st.st_mtime)})
    items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return jsonify(path=rel_of(d), items=items)


@app.get("/api/file")
def api_file_read():
    p = safe(request.args.get("path", ""))
    if not p.is_file():
        return jsonify(error="Fichier introuvable."), 404
    if p.stat().st_size > MAX_EDIT_BYTES:
        return jsonify(error="Fichier trop gros pour l'éditeur (1 Mo max). Télécharge-le."), 413
    try:
        return jsonify(content=p.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return jsonify(error="Fichier binaire : télécharge-le."), 415


@app.post("/api/file")
def api_file_write():
    data = request.get_json(silent=True) or {}
    p = safe(data.get("path", ""))
    if p.is_dir():
        return jsonify(error="C'est un dossier."), 400
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data.get("content", ""), encoding="utf-8")
    return jsonify(ok=True)


@app.get("/download")
def download():
    p = safe(request.args.get("path", ""))
    if not p.is_file():
        abort(404)
    return send_file(p, as_attachment=True, download_name=p.name)


@app.post("/api/upload")
def api_upload():
    d = safe(request.form.get("path", ""))
    d.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in request.files.getlist("files"):
        name = Path(f.filename or "").name
        if not name:
            continue
        f.save(d / name)
        n += 1
    return jsonify(ok=True, count=n)


@app.post("/api/mkdir")
def api_mkdir():
    safe((request.get_json(silent=True) or {}).get("path", "")).mkdir(parents=True, exist_ok=True)
    return jsonify(ok=True)


@app.post("/api/delete")
def api_delete():
    p = safe((request.get_json(silent=True) or {}).get("path", ""))
    if p == BOT_DIR:
        return jsonify(error="Impossible de supprimer le dossier racine."), 400
    if p.is_dir():
        shutil.rmtree(p)
    elif p.exists():
        p.unlink()
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# Sauvegarde / restauration (bases JSON, token, .env)
# --------------------------------------------------------------------------
def _is_backup_name(name: str) -> bool:
    return "/" not in name and "\\" not in name and (
        name in BACKUP_NAMES or name.endswith(BACKUP_PATTERNS))


@app.get("/backup.zip")
def backup():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(BOT_DIR.iterdir()):
            if f.is_file() and _is_backup_name(f.name):
                z.write(f, f.name)
    buf.seek(0)
    stamp = time.strftime("%Y%m%d-%H%M")
    return send_file(buf, as_attachment=True, download_name=f"sauvegarde-bot-{stamp}.zip",
                     mimetype="application/zip")


@app.post("/api/restore")
def restore():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Aucun fichier reçu."), 400
    try:
        z = zipfile.ZipFile(io.BytesIO(f.read()))
    except zipfile.BadZipFile:
        return jsonify(error="Ce fichier n'est pas un zip valide."), 400
    restored = []
    for info in z.infolist():
        if info.is_dir() or not _is_backup_name(info.filename):
            continue
        (BOT_DIR / info.filename).write_bytes(z.read(info))
        restored.append(info.filename)
    return jsonify(ok=True, files=restored)


# --------------------------------------------------------------------------
# Terminal
# --------------------------------------------------------------------------
@app.post("/api/exec")
def api_exec():
    cmd = ((request.get_json(silent=True) or {}).get("cmd") or "").strip()
    if not cmd:
        return jsonify(error="Commande vide."), 400
    try:
        r = subprocess.run(cmd, shell=True, cwd=str(BOT_DIR), capture_output=True,
                           text=True, errors="replace", timeout=600)
        out = (r.stdout or "") + (r.stderr or "")
        code = r.returncode
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
        out += "\n[délai de 10 min dépassé, commande interrompue]"
        code = -1
    if len(out) > 40000:
        out = "[…début tronqué…]\n" + out[-40000:]
    return jsonify(output=out, code=code)


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#12161c">
<title>Panel du bot</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,600;12..96,800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --night:#12161c; --panel:#1a2029; --raise:#222a35; --line:#2d3745;
  --text:#e7ebf0; --muted:#8f9bab; --sky:#35a8ee; --sky-ink:#06202f;
  --ok:#4cc38a; --bad:#ef6a5e; --warn:#e8b64a;
  --sans:"Bricolage Grotesque",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--night);color:var(--text);font-family:var(--sans);font-size:16px;line-height:1.5;-webkit-text-size-adjust:100%}
body{min-height:100dvh;padding-bottom:calc(76px + env(safe-area-inset-bottom,0px))}
button,input,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--sky);outline-offset:2px}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line)}
header h1{margin:0;font-size:1.05rem;font-weight:800;letter-spacing:.01em}
.linkbtn{background:none;border:0;color:var(--muted);padding:6px 4px;cursor:pointer;font-size:.95rem}
.linkbtn:hover{color:var(--text)}
main{max-width:860px;margin:0 auto;padding:20px 18px}
section[hidden]{display:none}
h2{font-size:1.15rem;font-weight:600;margin:28px 0 10px}
p.hint{color:var(--muted);font-size:.92rem;margin:6px 0 14px;max-width:62ch}

/* Statut : l'élément mémorable — un sticker découpé */
.hero{display:flex;flex-direction:column;align-items:flex-start;gap:14px;padding:8px 0 4px}
.sticker{display:inline-block;font-weight:800;font-size:2.1rem;line-height:1;padding:14px 22px;border-radius:20px;
  border:4px solid #fff;color:#0c1a13;background:var(--ok);transform:rotate(-2deg);
  box-shadow:0 0 0 1px rgba(0,0,0,.5),0 10px 22px rgba(0,0,0,.45);transition:background .25s,color .25s}
.sticker.off{background:var(--bad);color:#2b0b07}
.sticker.wait{background:var(--raise);color:var(--muted)}
.meta{color:var(--muted);font-size:.98rem}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}
.btn{border:1px solid var(--line);background:var(--raise);padding:12px 18px;border-radius:12px;font-weight:600;cursor:pointer;min-height:46px}
.btn:hover:not(:disabled){border-color:var(--sky)}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn.primary{background:var(--sky);border-color:var(--sky);color:var(--sky-ink)}
.btn.danger{border-color:var(--bad);color:var(--bad);background:transparent}
.btn.small{padding:8px 12px;min-height:38px;font-size:.92rem}
a.btn{display:inline-flex;align-items:center;text-decoration:none;color:inherit}

dl.stats{display:grid;grid-template-columns:auto 1fr;gap:8px 18px;margin:0;padding:16px;background:var(--panel);border:1px solid var(--line);border-radius:14px}
dl.stats dt{color:var(--muted)} dl.stats dd{margin:0;font-family:var(--mono);font-size:.92rem;word-break:break-all}

pre.term,.logbox{font-family:var(--mono);font-size:.8rem;line-height:1.55;background:#0d1015;border:1px solid var(--line);border-radius:12px;padding:12px;margin:0;overflow:auto;white-space:pre-wrap;word-break:break-word}
.logbox{height:min(62dvh,560px)}
.logbox .e{color:var(--bad)} .logbox .w{color:var(--warn)} .logbox .p{color:var(--sky)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}

.crumbs{font-family:var(--mono);font-size:.88rem;color:var(--muted);margin-bottom:10px;word-break:break-all}
.crumbs button{background:none;border:0;color:var(--sky);cursor:pointer;padding:2px 0;font:inherit}
ul.files{list-style:none;margin:0;padding:0;border:1px solid var(--line);border-radius:14px;overflow:hidden}
ul.files li{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:13px 14px;background:var(--panel);cursor:pointer;border-top:1px solid var(--line)}
ul.files li:first-child{border-top:0}
ul.files li:hover{background:var(--raise)}
ul.files .n{font-family:var(--mono);font-size:.9rem;word-break:break-all}
ul.files .s{color:var(--muted);font-size:.8rem;white-space:nowrap}
.empty{color:var(--muted);padding:18px;text-align:center}

.editor{position:fixed;inset:0;background:var(--night);z-index:20;display:flex;flex-direction:column}
.editor[hidden]{display:none}
.editor .bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px 14px;border-bottom:1px solid var(--line)}
.editor .name{font-family:var(--mono);font-size:.88rem;color:var(--muted);flex:1;min-width:140px;word-break:break-all}
.editor textarea{flex:1;width:100%;border:0;background:#0d1015;padding:14px;font-family:var(--mono);font-size:.85rem;line-height:1.55;resize:none;tab-size:4;white-space:pre}

.cmd{display:flex;gap:8px;margin:10px 0}
.cmd input{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;font-family:var(--mono);font-size:.9rem}
.chips{display:flex;gap:8px;flex-wrap:wrap}

nav{position:fixed;left:0;right:0;bottom:0;background:var(--panel);border-top:1px solid var(--line);display:flex;justify-content:center;padding-bottom:env(safe-area-inset-bottom,0px);z-index:10}
nav button{flex:1;max-width:215px;background:none;border:0;padding:14px 6px;color:var(--muted);font-weight:600;cursor:pointer;border-top:3px solid transparent;margin-top:-1px}
nav button[aria-selected=true]{color:var(--text);border-top-color:var(--sky)}

#toast{position:fixed;left:50%;bottom:calc(92px + env(safe-area-inset-bottom,0px));transform:translateX(-50%);background:var(--text);color:var(--night);padding:10px 16px;border-radius:12px;font-weight:600;opacity:0;pointer-events:none;transition:opacity .2s;z-index:30;max-width:90vw;text-align:center}
#toast.show{opacity:1} #toast.err{background:var(--bad);color:#fff}

.login{max-width:380px;margin:18dvh auto 0;padding:0 22px}
.login h1{font-size:1.7rem;font-weight:800;margin:0 0 6px}
.login input{width:100%;margin:14px 0;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;font-size:1rem}
.login .btn{width:100%}
.login .err{color:var(--bad);min-height:1.4em;margin:0}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div id="app" hidden>
<header><h1>Panel du bot</h1><button class="linkbtn" id="logout">Se déconnecter</button></header>
<main>
  <section id="tab-bot">
    <div class="hero">
      <span class="sticker wait" id="badge">…</span>
      <div class="meta" id="meta">Chargement…</div>
      <div class="actions">
        <button class="btn primary" id="b-start">Démarrer</button>
        <button class="btn" id="b-restart">Redémarrer</button>
        <button class="btn danger" id="b-stop">Arrêter</button>
      </div>
    </div>
    <h2>Détails</h2>
    <dl class="stats" id="stats"></dl>
    <h2>Sauvegarde</h2>
    <p class="hint">Les bases JSON, token.txt et .env sont perdus si le serveur est réinitialisé. Télécharge une sauvegarde de temps en temps, et restaure-la après un redéploiement.</p>
    <div class="actions">
      <a class="btn" href="/backup.zip">Télécharger la sauvegarde</a>
      <button class="btn" id="b-restore">Restaurer une sauvegarde</button>
      <input type="file" id="restore-file" accept=".zip" hidden>
    </div>
  </section>

  <section id="tab-logs" hidden>
    <div class="toolbar">
      <button class="btn small" id="l-clear">Vider l'affichage</button>
      <button class="btn small" id="l-copy">Copier</button>
    </div>
    <div class="logbox" id="logbox" role="log" aria-live="off"></div>
  </section>

  <section id="tab-files" hidden>
    <div class="crumbs" id="crumbs"></div>
    <div class="toolbar">
      <button class="btn small" id="f-upload">Importer des fichiers</button>
      <button class="btn small" id="f-mkdir">Nouveau dossier</button>
      <input type="file" id="upload-input" multiple hidden>
    </div>
    <ul class="files" id="files"></ul>
  </section>

  <section id="tab-term" hidden>
    <p class="hint">Les commandes s'exécutent dans le dossier du bot, avec une limite de 10 minutes.</p>
    <div class="chips">
      <button class="btn small" data-cmd="pip install -r requirements.txt rlottie-python">Installer les dépendances Python</button>
      <button class="btn small" data-cmd="apt-get update && apt-get install -y ffmpeg">Installer ffmpeg</button>
      <button class="btn small" data-cmd="ls -la">Lister les fichiers</button>
    </div>
    <div class="cmd">
      <input id="cmd" placeholder="Commande, par ex. python3 --version" autocapitalize="off" autocomplete="off" spellcheck="false">
      <button class="btn primary" id="c-run">Exécuter</button>
    </div>
    <pre class="term" id="term">Aucune commande lancée.</pre>
  </section>
</main>

<div class="editor" id="editor" hidden>
  <div class="bar">
    <span class="name" id="ed-name"></span>
    <button class="btn small primary" id="ed-save">Enregistrer</button>
    <a class="btn small" id="ed-dl" href="#">Télécharger</a>
    <button class="btn small danger" id="ed-del">Supprimer</button>
    <button class="btn small" id="ed-close">Fermer</button>
  </div>
  <textarea id="ed-text" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea>
</div>

<nav role="tablist">
  <button role="tab" data-tab="bot" aria-selected="true">Bot</button>
  <button role="tab" data-tab="logs" aria-selected="false">Logs</button>
  <button role="tab" data-tab="files" aria-selected="false">Fichiers</button>
  <button role="tab" data-tab="term" aria-selected="false">Terminal</button>
</nav>
</div>

<div class="login" id="login" hidden>
  <h1>Panel du bot</h1>
  <p class="meta">Entre le mot de passe pour continuer.</p>
  <input type="password" id="pw" placeholder="Mot de passe" autocomplete="current-password">
  <p class="err" id="login-err"></p>
  <button class="btn primary" id="login-btn">Se connecter</button>
</div>
<div id="toast" role="status"></div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
let tab = 'bot', lastSeq = 0, cwd = '', editPath = '';

function toast(msg, err){const t=$('#toast');t.textContent=msg;t.className='show'+(err?' err':'');clearTimeout(toast.h);toast.h=setTimeout(()=>t.className='',2600)}
async function api(url, opts={}){
  opts.headers = Object.assign({'X-Panel':'1'}, opts.headers||{});
  const r = await fetch(url, opts);
  let d = {}; try{ d = await r.json() }catch(e){}
  if(r.status===401 && url!=='/api/login'){ showLogin(); throw new Error('session') }
  if(!r.ok) throw new Error(d.error || ('Erreur '+r.status));
  return d;
}
const post = (url, body) => api(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
const fmtDur = s => { if(s<60) return s+' s'; const m=Math.floor(s/60); if(m<60) return m+' min'; const h=Math.floor(m/60); if(h<24) return h+' h '+(m%60)+' min'; return Math.floor(h/24)+' j '+(h%24)+' h'; };
const fmtSize = n => n<1024?n+' o':n<1048576?(n/1024).toFixed(1)+' Ko':(n/1048576).toFixed(1)+' Mo';
function addRow(dl, k, v){const a=document.createElement('dt');a.textContent=k;const b=document.createElement('dd');b.textContent=v;dl.append(a,b)}

/* ---------- connexion ---------- */
function showLogin(){ $('#app').hidden=true; $('#login').hidden=false; $('#pw').focus() }
async function tryLogin(){
  try{ await post('/api/login',{password:$('#pw').value}); $('#login').hidden=true; $('#app').hidden=false; boot() }
  catch(e){ $('#login-err').textContent=e.message }
}
$('#login-btn').onclick = tryLogin;
$('#pw').onkeydown = e => { if(e.key==='Enter') tryLogin() };
$('#logout').onclick = async () => { await post('/api/logout'); showLogin() };

/* ---------- onglets ---------- */
$$('nav button').forEach(b => b.onclick = () => {
  tab = b.dataset.tab;
  $$('nav button').forEach(x => x.setAttribute('aria-selected', x===b));
  ['bot','logs','files','term'].forEach(t => $('#tab-'+t).hidden = t!==tab);
  if(tab==='files') loadFiles(cwd);
  if(tab==='logs') pollLogs();
  if(tab==='bot') pollStatus();
});

/* ---------- bot ---------- */
async function pollStatus(){
  if(tab!=='bot' || $('#app').hidden) return;
  try{
    const s = await api('/api/status');
    const b = $('#badge');
    b.textContent = s.running ? 'En marche' : 'Arrêté';
    b.className = 'sticker' + (s.running ? '' : ' off');
    let meta = s.running ? 'Actif depuis ' + fmtDur(s.uptime) : (s.last_exit===null ? 'Le bot n’a pas encore été lancé.' : 'Dernier code de sortie : '+s.last_exit);
    if(s.restarts) meta += ' · ' + s.restarts + ' relance(s) automatique(s)';
    $('#meta').textContent = meta;
    $('#b-start').disabled = s.running || !s.has_bot;
    $('#b-restart').disabled = !s.has_bot;
    $('#b-stop').disabled = !s.running;
    const dl = $('#stats'); dl.textContent='';
    addRow(dl,'Dossier',s.bot_dir);
    addRow(dl,'PID',s.pid ?? '—');
    addRow(dl,'Mémoire',s.ram_mb!=null ? s.ram_mb+' Mo' : (s.psutil?'—':'psutil non installé'));
    addRow(dl,'Processeur',s.cpu!=null ? s.cpu+' %' : (s.psutil?'—':'psutil non installé'));
    if(!s.has_bot) toast('bot.py est introuvable dans le dossier du bot.', true);
  }catch(e){}
}
async function botAction(a, ok){
  try{ await post('/api/bot/'+a); toast(ok); setTimeout(pollStatus,600) }catch(e){ toast(e.message,true) }
}
$('#b-start').onclick = () => botAction('start','Bot démarré');
$('#b-restart').onclick = () => botAction('restart','Bot redémarré');
$('#b-stop').onclick = () => { if(confirm('Arrêter le bot ?')) botAction('stop','Bot arrêté') };
$('#b-restore').onclick = () => $('#restore-file').click();
$('#restore-file').onchange = async e => {
  const f = e.target.files[0]; if(!f) return;
  if(!confirm('Restaurer cette sauvegarde ? Les fichiers du même nom seront remplacés.')){ e.target.value=''; return }
  const fd = new FormData(); fd.append('file', f);
  try{ const d = await api('/api/restore',{method:'POST',body:fd}); toast(d.files.length+' fichier(s) restauré(s)') }
  catch(err){ toast(err.message,true) }
  e.target.value='';
};

/* ---------- logs ---------- */
function lineClass(t){ if(/Traceback|ERROR|Error|Exception|CRITICAL/.test(t)) return 'e'; if(/WARNING|WARN/.test(t)) return 'w'; if(t.startsWith('[panel]')) return 'p'; return ''; }
async function pollLogs(){
  if(tab!=='logs' || $('#app').hidden) return;
  try{
    const d = await api('/api/logs?after='+lastSeq);
    if(d.last < lastSeq) { lastSeq = 0; $('#logbox').textContent=''; }
    if(d.lines.length){
      const box = $('#logbox');
      const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
      for(const l of d.lines){
        const div = document.createElement('div'); div.textContent = l.t;
        const c = lineClass(l.t); if(c) div.className = c; box.append(div);
        lastSeq = l.n;
      }
      while(box.childElementCount > 1500) box.firstChild.remove();
      if(stick) box.scrollTop = box.scrollHeight;
    }
  }catch(e){}
}
$('#l-clear').onclick = () => { $('#logbox').textContent='' };
$('#l-copy').onclick = async () => {
  try{ await navigator.clipboard.writeText($('#logbox').innerText); toast('Logs copiés') }catch(e){ toast('Copie impossible ici',true) }
};

/* ---------- fichiers ---------- */
const join = (a,b) => a ? a+'/'+b : b;
async function loadFiles(path){
  try{
    const d = await api('/api/files?path='+encodeURIComponent(path||''));
    cwd = d.path;
    const cr = $('#crumbs'); cr.textContent='';
    const root = document.createElement('button'); root.textContent='bot'; root.onclick=()=>loadFiles(''); cr.append(root);
    let acc=''; for(const part of cwd.split('/').filter(Boolean)){
      acc = join(acc,part); const p=acc;
      cr.append(' / '); const b=document.createElement('button'); b.textContent=part; b.onclick=()=>loadFiles(p); cr.append(b);
    }
    const ul = $('#files'); ul.textContent='';
    if(!d.items.length){ const li=document.createElement('li'); li.className='empty'; li.textContent='Dossier vide. Importe des fichiers pour commencer.'; li.style.cursor='default'; ul.append(li); return }
    for(const it of d.items){
      const li=document.createElement('li');
      const n=document.createElement('span'); n.className='n'; n.textContent=(it.dir?'📁 ':'')+it.name;
      const s=document.createElement('span'); s.className='s'; s.textContent=it.dir?'':fmtSize(it.size);
      li.append(n,s);
      li.onclick = () => it.dir ? loadFiles(join(cwd,it.name)) : openFile(join(cwd,it.name));
      ul.append(li);
    }
  }catch(e){ toast(e.message,true) }
}
async function openFile(path){
  try{
    const d = await api('/api/file?path='+encodeURIComponent(path));
    editPath = path; $('#ed-name').textContent = path; $('#ed-text').value = d.content;
    $('#ed-dl').href = '/download?path='+encodeURIComponent(path);
    $('#editor').hidden = false;
  }catch(e){
    toast(e.message,true);
    if(/télécharge/i.test(e.message)) window.location = '/download?path='+encodeURIComponent(path);
  }
}
$('#ed-close').onclick = () => { $('#editor').hidden = true };
$('#ed-save').onclick = async () => {
  try{ await post('/api/file',{path:editPath,content:$('#ed-text').value}); toast('Fichier enregistré') }catch(e){ toast(e.message,true) }
};
$('#ed-del').onclick = async () => {
  if(!confirm('Supprimer '+editPath+' ?')) return;
  try{ await post('/api/delete',{path:editPath}); $('#editor').hidden=true; toast('Fichier supprimé'); loadFiles(cwd) }catch(e){ toast(e.message,true) }
};
$('#f-upload').onclick = () => $('#upload-input').click();
$('#upload-input').onchange = async e => {
  const files = [...e.target.files]; if(!files.length) return;
  const fd = new FormData(); fd.append('path', cwd); files.forEach(f=>fd.append('files',f));
  try{ const d = await api('/api/upload',{method:'POST',body:fd}); toast(d.count+' fichier(s) importé(s)'); loadFiles(cwd) }catch(err){ toast(err.message,true) }
  e.target.value='';
};
$('#f-mkdir').onclick = async () => {
  const name = prompt('Nom du nouveau dossier'); if(!name) return;
  try{ await post('/api/mkdir',{path:join(cwd,name)}); toast('Dossier créé'); loadFiles(cwd) }catch(e){ toast(e.message,true) }
};

/* ---------- terminal ---------- */
async function runCmd(cmd){
  if(!cmd) return;
  const t = $('#term'); t.textContent = '$ '+cmd+'\n\nExécution…';
  $('#c-run').disabled = true;
  try{ const d = await post('/api/exec',{cmd}); t.textContent = '$ '+cmd+'\n\n'+(d.output||'(aucune sortie)')+'\n[code de sortie : '+d.code+']'; t.scrollTop = t.scrollHeight }
  catch(e){ t.textContent = e.message }
  $('#c-run').disabled = false;
}
$('#c-run').onclick = () => runCmd($('#cmd').value.trim());
$('#cmd').onkeydown = e => { if(e.key==='Enter') runCmd($('#cmd').value.trim()) };
$$('[data-cmd]').forEach(b => b.onclick = () => { $('#cmd').value = b.dataset.cmd; runCmd(b.dataset.cmd) });

/* ---------- démarrage ---------- */
let timers = false;
function boot(){
  pollStatus();
  if(!timers){ timers = true; setInterval(pollStatus, 3000); setInterval(pollLogs, 1500) }
}
(async () => {
  try{ await api('/api/status'); $('#app').hidden=false; boot() }catch(e){ if(e.message!=='session') showLogin() }
})();
</script>
</body>
</html>
"""


@app.get("/")
@app.get("/login")
def index():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    if AUTOSTART and (BOT_DIR / "bot.py").is_file():
        bot.start()
    print(f"[panel] dossier du bot : {BOT_DIR}")
    print(f"[panel] écoute sur le port {PORT}", flush=True)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
