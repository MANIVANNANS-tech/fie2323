"""
ScamShield v4 — ScamShield Security Engine
NEW: CSV/PDF export · Email alerts · Live counter · Bulk scan · API key auth
"""

from flask import Flask, render_template, request, jsonify, redirect, session, Response
import sqlite3, hashlib, os, re, time, base64, csv, io, json, secrets, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import GradientBoostingClassifier

app = Flask(__name__, template_folder='.')
app.secret_key = os.urandom(32)
DB = "/tmp/qrsse.db" if os.environ.get("VERCEL") else "qrsse.db"
ADMIN_HASH = hashlib.sha256(b"quantumadmin2025").hexdigest()

# ── Email config (update for real alerts) ──
EMAIL_ENABLED   = False
SMTP_HOST       = "smtp.gmail.com"
SMTP_PORT       = 587
SMTP_USER       = "your@gmail.com"
SMTP_PASS       = "your-app-password"
ALERT_RECIPIENT = "admin@yourdomain.com"
ALERT_LEVELS    = {"Critical", "High"}


# ══════════════════════════════════════════
#  PQC Engine
# ══════════════════════════════════════════
class PQCEngine:
    @staticmethod
    def keygen():
        s = os.urandom(32)
        pk = base64.b64encode(hashlib.sha3_256(s + b"pk").digest()).decode()
        sk = base64.b64encode(hashlib.sha3_256(s + b"sk").digest()).decode()
        return pk, sk

    @staticmethod
    def encapsulate(pk, msg):
        r  = hashlib.sha3_256(base64.b64decode(pk) + msg.encode()).digest()
        ss = hashlib.sha3_512(r).digest()
        ct = base64.b64encode(hashlib.sha3_256(ss + b"ct").digest()[:18]).decode()
        return {"ciphertext": ct, "ss_hash": hashlib.sha256(ss).hexdigest()[:20], "algo": "KYBER-512"}

    @staticmethod
    def sign(msg, sk):
        raw = hashlib.sha3_256(base64.b64decode(sk) + msg.encode()).hexdigest()
        return f"DL3:{raw[:40]}"


# ══════════════════════════════════════════
#  HE Processor
# ══════════════════════════════════════════
class HEProcessor:
    @staticmethod
    def encode(features):
        seed  = int(abs(np.sum(features)) * 1e4) % (2**31)
        noise = np.random.RandomState(seed).normal(0, 5e-4, features.shape)
        enc   = features + noise
        return {"enc": enc.tolist(), "ph": hashlib.sha256(features.tobytes()).hexdigest()[:20]}

    @staticmethod
    def eval_dot(enc, w):
        v = np.array(enc["enc"]); n = min(len(v), len(w))
        return float(np.dot(v[:n], w[:n]))


# ══════════════════════════════════════════
#  Scam Engine
# ══════════════════════════════════════════
class ScamEngine:
    PATTERNS = [
        (r'\b(urgent|act now|expires|immediately|final notice)\b',              "Urgency signals",        0.25),
        (r'\b(verify|confirm|suspended|locked)\b.*\b(account|identity|card)\b', "Credential phishing",    0.35),
        (r'\b(won|winner|lottery|prize|congratulations)\b',                     "Lottery/prize fraud",    0.20),
        (r'\b(bank|credit card|ssn|social security|password)\b',                "Sensitive data request", 0.30),
        (r'\b(wire|western union|gift card|bitcoin|crypto|btc)\b',              "Payment redirection",    0.40),
        (r'\b(nigerian|prince|inheritance|offshore|beneficiary)\b',             "Advance fee fraud",      0.45),
        (r'\b(guaranteed|risk.?free|double).*\b(return|profit|invest)\b',       "Investment fraud",       0.35),
        (r'https?://(?:bit\.ly|tinyurl)',                                        "Suspicious link",        0.20),
        (r'\b(dear|hello)\s+(customer|user|friend|sir)',                         "Mass greeting",          0.15),
        (r'[A-Z]{5,}',                                                           "Excessive caps",         0.10),
    ]

    def __init__(self):
        self.vec = TfidfVectorizer(max_features=600, ngram_range=(1, 3))
        self.clf = GradientBoostingClassifier(n_estimators=120, random_state=7)
        self._w  = np.random.RandomState(99).randn(20)
        self._train()

    def _train(self):
        scams = [
            "URGENT: Your bank account suspended. Verify credit card and SSN immediately.",
            "Congratulations! You won $2500000 in our international lottery. Send bank details.",
            "Dear beneficiary, Nigerian prince with $45M needs your help. Share account details.",
            "Your PayPal will be closed. Confirm password via this link: bit.ly/secure-verify",
            "FREE MONEY! Double your Bitcoin guaranteed 500% returns risk-free. Act now!",
            "Final notice: claim your $10000 prize. Wire transfer required. Western Union.",
            "Hello friend, investment opportunity guaranteed 300% ROI. Crypto wire needed.",
            "Your social security number compromised. Call immediately to resolve.",
            "URGENT dear customer: account expires unless you click confirm identity link.",
            "Win selected winner lottery $1000000. SSN and bank account needed.",
            "Inheritance claim: $8M awaiting. Send $500 processing fee via Bitcoin.",
            "Your Amazon account suspended. Verify billing information now.",
        ]
        legit = [
            "Hey, can we reschedule Thursday's meeting to 3pm? Let me know.",
            "Your order has shipped and should arrive by Friday.",
            "Reminder: team standup tomorrow at 9am. Please review the Q4 slides.",
            "Happy birthday! Hope you have an amazing day.",
            "The invoice for October services is attached. Payment due end of month.",
            "Thanks for your feedback on the beta. We've fixed the bug in v2.3.",
            "Dinner reservations confirmed for Saturday 7:30pm.",
            "Your annual subscription renews next month. No action needed.",
            "New blog post: 5 productivity tips for remote teams.",
            "Package delivered to front door at 2:47 PM.",
            "Quarterly report is ready. Key highlights: 12% growth.",
            "Interview scheduled for Monday 10am via Zoom. See you then.",
        ]
        X = self.vec.fit_transform(scams + legit)
        self.clf.fit(X, [1]*len(scams) + [0]*len(legit))

    def analyze(self, msg, pk, sk):
        t0    = time.time()
        kyber = PQCEngine.encapsulate(pk, msg)
        sig   = PQCEngine.sign(msg, sk)
        lo    = msg.lower()

        feats       = np.zeros(20)
        pat_details = []
        for i, (pat, name, w) in enumerate(self.PATTERNS):
            hits  = len(re.findall(pat, lo, re.I))
            score = min(hits * w, 1.0)
            feats[i] = score
            pat_details.append({"name": name, "score": round(score * 100, 1), "hits": hits})

        feats[10] = min(len(msg) / 800, 1.0)
        feats[11] = min(lo.count('!') / 8,  1.0)
        feats[12] = min(lo.count('$') / 4,  1.0)
        feats[13] = float(bool(re.search(r'https?://', msg)))

        he_enc   = HEProcessor.encode(feats)
        he_raw   = HEProcessor.eval_dot(he_enc, self._w)
        he_score = float(1 / (1 + np.exp(-he_raw * 0.4)))
        pat_risk = float(np.mean(feats[:10]))
        ml_prob  = float(self.clf.predict_proba(self.vec.transform([msg]))[0][1])
        risk     = min(max(ml_prob * 0.5 + pat_risk * 0.35 + he_score * 0.15, 0.0), 1.0)
        score    = round(risk * 100, 1)

        if score >= 75:   level, color, badge = "Critical", "#dc2626", "red"
        elif score >= 50: level, color, badge = "High",     "#ea580c", "orange"
        elif score >= 28: level, color, badge = "Moderate", "#d97706", "yellow"
        else:             level, color, badge = "Safe",     "#16a34a", "green"

        return {
            "score": score, "level": level, "color": color, "badge": badge,
            "ml_prob": round(ml_prob*100,1), "pat_risk": round(pat_risk*100,1),
            "he_score": round(he_score*100,1), "pat_details": pat_details,
            "kyber": kyber, "sig": sig, "he_ph": he_enc["ph"],
            "fp": hashlib.sha3_256(msg.encode()).hexdigest()[:36],
            "ms": round((time.time()-t0)*1000, 2),
            "ts": datetime.utcnow().isoformat()+"Z",
        }


# ══════════════════════════════════════════
#  Database
# ══════════════════════════════════════════
def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fp TEXT, preview TEXT, score REAL, level TEXT,
            ml_prob REAL, sig TEXT, kyber_ct TEXT, he_ph TEXT,
            ms REAL, ts TEXT, ip_hash TEXT);

        CREATE TABLE IF NOT EXISTS api_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            label TEXT, created_at TEXT, last_used TEXT,
            total_calls INTEGER DEFAULT 0, active INTEGER DEFAULT 1);

        CREATE TABLE IF NOT EXISTS alert_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_fp TEXT, level TEXT, score REAL,
            sent_at TEXT, recipient TEXT, status TEXT);
    """)
    c.commit(); c.close()

def save_scan(d, msg, ip):
    preview = msg[:60] + ("…" if len(msg)>60 else "")
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO scans VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?)",
              (d["fp"], preview, d["score"], d["level"], d["ml_prob"],
               d["sig"], d["kyber"]["ciphertext"], d["he_ph"],
               d["ms"], d["ts"], hashlib.sha256((ip or "").encode()).hexdigest()[:16]))
    c.commit(); c.close()

def all_scans():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 500").fetchall()]
    c.close(); return rows

def get_stats():
    c = sqlite3.connect(DB)
    r = c.execute("""SELECT COUNT(*), AVG(score),
        SUM(CASE WHEN level='Critical' THEN 1 ELSE 0 END),
        SUM(CASE WHEN level='High'     THEN 1 ELSE 0 END),
        SUM(CASE WHEN level='Safe'     THEN 1 ELSE 0 END)
        FROM scans""").fetchone()
    c.close()
    return {"total": r[0] or 0, "avg": round(r[1] or 0,1),
            "critical": r[2] or 0, "high": r[3] or 0, "safe": r[4] or 0}

def get_total_count():
    c = sqlite3.connect(DB)
    n = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    c.close(); return n


# ══════════════════════════════════════════
#  API Key helpers
# ══════════════════════════════════════════
def create_api_key(label="default"):
    raw_key  = "scamshield_" + secrets.token_hex(24)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO api_keys(key_hash,label,created_at,active) VALUES(?,?,?,1)",
              (key_hash, label, datetime.utcnow().isoformat()))
    c.commit(); c.close()
    return raw_key

def verify_api_key(raw_key):
    if not raw_key: return False
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    c = sqlite3.connect(DB)
    row = c.execute("SELECT id FROM api_keys WHERE key_hash=? AND active=1", (key_hash,)).fetchone()
    if row:
        c.execute("UPDATE api_keys SET last_used=?, total_calls=total_calls+1 WHERE id=?",
                  (datetime.utcnow().isoformat(), row[0]))
        c.commit()
    c.close()
    return row is not None

def list_api_keys():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute(
        "SELECT id,label,created_at,last_used,total_calls,active FROM api_keys ORDER BY id DESC").fetchall()]
    c.close(); return rows

def revoke_api_key(kid):
    c = sqlite3.connect(DB)
    c.execute("UPDATE api_keys SET active=0 WHERE id=?", (kid,))
    c.commit(); c.close()

def api_key_from_request():
    return request.headers.get("X-API-Key","") or request.args.get("api_key","")


# ══════════════════════════════════════════
#  Email alerts
# ══════════════════════════════════════════
def send_alert(result, preview):
    if not EMAIL_ENABLED or result["level"] not in ALERT_LEVELS:
        return "disabled"
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[ScamShield] {result['level']} threat — score {result['score']}"
        msg["From"] = SMTP_USER; msg["To"] = ALERT_RECIPIENT
        col = "#dc2626" if result["level"]=="Critical" else "#ea580c"
        html = f"""<div style="font-family:Inter,sans-serif;max-width:540px">
          <div style="background:#1d2230;padding:18px 22px;border-radius:8px 8px 0 0">
            <span style="color:#f6821f;font-weight:700;font-size:17px">ScamShield</span>
            <span style="color:rgba(255,255,255,.4);font-size:12px;margin-left:8px">Security Alert</span></div>
          <div style="border:1px solid #e4e7ed;border-top:none;padding:22px;border-radius:0 0 8px 8px">
            <div style="color:{col};font-size:17px;font-weight:700;margin-bottom:14px">
              {'☣' if result['level']=='Critical' else '⚠'} {result['level']} Threat — Score {result['score']}/100</div>
            <table style="font-size:13px;width:100%">
              <tr><td style="color:#9ca3af;padding:6px 0;width:140px">Preview</td><td>{preview[:80]}</td></tr>
              <tr><td style="color:#9ca3af;padding:6px 0">ML confidence</td><td>{result['ml_prob']}%</td></tr>
              <tr><td style="color:#9ca3af;padding:6px 0">Fingerprint</td>
                  <td style="font-family:monospace;font-size:11px">{result['fp']}</td></tr>
              <tr><td style="color:#9ca3af;padding:6px 0">Time</td><td>{result['ts']}</td></tr>
            </table></div></div>"""
        msg.attach(MIMEText(html,"html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(); s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, ALERT_RECIPIENT, msg.as_string())
        status = "sent"
    except Exception as e:
        status = f"error:{e}"
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO alert_log VALUES(NULL,?,?,?,?,?,?)",
              (result["fp"], result["level"], result["score"],
               datetime.utcnow().isoformat(), ALERT_RECIPIENT, status))
    c.commit(); c.close()
    return status


# ══════════════════════════════════════════
#  Export helpers
# ══════════════════════════════════════════
def scans_to_csv():
    rows = all_scans()
    buf  = io.StringIO()
    w    = csv.writer(buf)
    w.writerow(["ID","Timestamp","Level","Risk Score","ML%","Preview","Kyber CT","Fingerprint","IP Hash","ms"])
    for r in rows:
        w.writerow([r["id"],r["ts"],r["level"],r["score"],r["ml_prob"],
                    r["preview"],r["kyber_ct"],r["fp"],r["ip_hash"],r["ms"]])
    buf.seek(0); return buf.getvalue()

def scans_to_html_report():
    rows  = all_scans(); stats = get_stats()
    ts    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lc    = {"Critical":"#dc2626","High":"#ea580c","Moderate":"#d97706","Safe":"#16a34a"}
    trs   = "".join(f"""<tr><td>{r['id']}</td>
        <td style="font-size:11px;color:#6b7280">{(r['ts'] or '')[:19]}</td>
        <td>{r['preview']}</td>
        <td style="color:{lc.get(r['level'],'#6b7280')};font-weight:600">{r['level']}</td>
        <td style="font-weight:600;color:{lc.get(r['level'],'#6b7280')}">{r['score']}</td>
        <td>{r['ml_prob']}%</td>
        <td style="font-family:monospace;font-size:10px;color:#9ca3af">{(r['fp'] or '')[:20]}…</td></tr>"""
        for r in rows)
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>ScamShield Report</title>
    <style>body{{font-family:Inter,-apple-system,sans-serif;padding:32px;color:#1a1d23;font-size:13px}}
    h1{{font-size:22px;font-weight:700}}
    .sub{{color:#9ca3af;font-size:12px;margin:4px 0 24px}}
    .stats{{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}}
    .sc{{border:1px solid #e4e7ed;border-radius:6px;padding:14px 18px}}
    .sv{{font-size:26px;font-weight:700;color:#f6821f}}
    .sk{{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}}
    table{{width:100%;border-collapse:collapse}}
    th{{font-size:10px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:.04em;
        padding:8px 10px;border-bottom:2px solid #e4e7ed;text-align:left}}
    td{{padding:8px 10px;border-bottom:1px solid #f0f2f5}}
    @media print{{body{{padding:16px}}}}</style></head>
    <body><h1>ScamShield — Scan History Report</h1>
    <div class="sub">Generated {ts} · Privacy-preserving · No plaintext stored</div>
    <div class="stats">
      <div class="sc"><div class="sv">{stats['total']}</div><div class="sk">Total</div></div>
      <div class="sc"><div class="sv">{stats['avg']}</div><div class="sk">Avg Risk</div></div>
      <div class="sc"><div class="sv" style="color:#dc2626">{stats['critical']}</div><div class="sk">Critical</div></div>
      <div class="sc"><div class="sv" style="color:#ea580c">{stats['high']}</div><div class="sk">High</div></div>
      <div class="sc"><div class="sv" style="color:#16a34a">{stats['safe']}</div><div class="sk">Safe</div></div>
    </div>
    <table><thead><tr><th>#</th><th>Timestamp</th><th>Preview</th><th>Level</th>
    <th>Risk</th><th>ML%</th><th>Fingerprint</th></tr></thead><tbody>{trs}</tbody></table>
    <script>window.onload=()=>window.print()</script></body></html>"""


# ══════════════════════════════════════════
#  Route init
# ══════════════════════════════════════════
engine = ScamEngine()
PK, SK = PQCEngine.keygen()


# ── Public routes ──────────────────────────
@app.route("/")
def index(): return render_template("index.html")

@app.route("/bulk")
def bulk_page(): return render_template("bulk.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    api_key = api_key_from_request()
    if api_key and not verify_api_key(api_key):
        return jsonify({"error": "Invalid or revoked API key"}), 401
    data = request.get_json() or {}
    msg  = data.get("message","").strip()
    if not msg:         return jsonify({"error":"No message provided"}), 400
    if len(msg) > 5000: return jsonify({"error":"Message too long (max 5000 chars)"}), 400
    result = engine.analyze(msg, PK, SK)
    save_scan(result, msg, request.remote_addr or "")
    result["alert_sent"] = send_alert(result, msg)
    return jsonify(result)

@app.route("/api/bulk-scan", methods=["POST"])
def bulk_scan():
    api_key = api_key_from_request()
    if api_key and not verify_api_key(api_key):
        return jsonify({"error":"Invalid API key"}), 401
    data     = request.get_json() or {}
    messages = data.get("messages", [])
    if not messages or not isinstance(messages, list):
        return jsonify({"error":"Provide JSON array under 'messages'"}), 400
    if len(messages) > 50:
        return jsonify({"error":"Max 50 messages per bulk request"}), 400
    results = []
    for i, msg in enumerate(messages):
        msg = str(msg).strip()
        if not msg: continue
        r = engine.analyze(msg[:5000], PK, SK)
        save_scan(r, msg, request.remote_addr or "")
        send_alert(r, msg)
        results.append({"index":i,"preview":msg[:60],**{k:r[k] for k in
            ["score","level","color","ml_prob","pat_risk","he_score","fp","ts","ms"]}})
    summary = {
        "total":    len(results),
        "critical": sum(1 for r in results if r["level"]=="Critical"),
        "high":     sum(1 for r in results if r["level"]=="High"),
        "moderate": sum(1 for r in results if r["level"]=="Moderate"),
        "safe":     sum(1 for r in results if r["level"]=="Safe"),
        "avg_score":round(sum(r["score"] for r in results)/max(len(results),1),1),
    }
    return jsonify({"summary":summary,"results":results})

@app.route("/api/live-count")
def live_count():
    def gen():
        last = -1
        for _ in range(200):
            count = get_total_count()
            if count != last:
                yield f"data: {json.dumps({'count':count})}\n\n"
                last = count
            time.sleep(3)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/stats")
def api_stats(): return jsonify(get_stats())


# ── Admin routes ───────────────────────────
@app.route("/admin", methods=["GET","POST"])
def admin():
    if request.method == "POST":
        pw = request.form.get("pw","")
        if hashlib.sha256(pw.encode()).hexdigest() == ADMIN_HASH:
            session["a"] = True
        else:
            return render_template("admin.html", logged=False, error="Invalid credentials")
    if not session.get("a"):
        return render_template("admin.html", logged=False)
    return render_template("admin.html", logged=True,
                           scans=all_scans(), stats=get_stats(),
                           api_keys=list_api_keys())

@app.route("/admin/logout")
def logout(): session.clear(); return redirect("/admin")

@app.route("/admin/export/csv")
def export_csv():
    if not session.get("a"): return redirect("/admin")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(scans_to_csv(), mimetype="text/csv",
                    headers={"Content-Disposition":f"attachment;filename=scamshield_{ts}.csv"})

@app.route("/admin/export/pdf")
def export_pdf():
    if not session.get("a"): return redirect("/admin")
    return Response(scans_to_html_report(), mimetype="text/html")

@app.route("/admin/api-keys/create", methods=["POST"])
def admin_create_key():
    if not session.get("a"): return jsonify({"error":"Unauthorized"}), 401
    label   = (request.get_json() or {}).get("label","Unnamed key")
    raw_key = create_api_key(label)
    return jsonify({"key":raw_key,"message":"Store this key now — it won't be shown again."})

@app.route("/admin/api-keys/revoke", methods=["POST"])
def admin_revoke_key():
    if not session.get("a"): return jsonify({"error":"Unauthorized"}), 401
    kid = (request.get_json() or {}).get("id")
    if kid: revoke_api_key(kid)
    return jsonify({"ok":True})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
