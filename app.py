"""
VulnLab — a deliberately vulnerable practice target for VulnScan Pro.
=======================================================================
This app exists ONLY so you have something legal to point your own
scanner at. Every bug in here is intentional. Do not deploy this
anywhere public-facing that isn't throwaway, and never reuse this code
in a real project.

Three GET-param endpoints, each with a different severity so a scan
produces a nice spread of findings:

  /products?id=1          -> SQL Injection            (HIGH / CRITICAL)
  /profile?bio=hello       -> Reflected XSS             (MEDIUM / HIGH)
  /go?next=/products       -> Open Redirect             (LOW / MEDIUM)

It also deliberately omits security headers and sets a weak cookie,
so the "Headers" and "Cookies" modules in VulnScan Pro have something
to report too.
"""

from flask import Flask, request, make_response, redirect
import sqlite3
import os

app = Flask(__name__)
DB_PATH = "/tmp/vulnlab.db"


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT, price TEXT)")
    conn.executemany(
        "INSERT INTO products VALUES (?,?,?)",
        [
            (1, "USB Cable", "$4.99"),
            (2, "Wireless Mouse", "$14.50"),
            (3, "Mechanical Keyboard", "$59.00"),
            (4, "Admin Debug Token", "classified"),  # the "secret row" a successful SQLi can pull out
        ],
    )
    conn.commit()
    conn.close()


init_db()

PAGE_HEAD = """<!doctype html>
<html><head><meta charset="utf-8"><title>VulnLab</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 20px;color:#222}
h1{color:#b91c1c}
nav a{margin-right:14px}
code{background:#f3f4f6;padding:2px 6px;border-radius:4px}
table{border-collapse:collapse;width:100%;margin-top:12px}
td,th{border:1px solid #ddd;padding:8px;text-align:left;font-size:14px}
.warn{background:#fef3c7;border:1px solid #f59e0b;padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:20px}
</style></head><body>
<div class="warn">⚠ VulnLab is intentionally vulnerable. Use only against this instance, only for learning / testing your own scanner.</div>
<nav><a href="/">home</a><a href="/products?id=1">products (SQLi)</a><a href="/profile?bio=hello">profile (XSS)</a><a href="/go?next=/products">redirect (open redirect)</a></nav>
<hr>
"""


@app.route("/")
def index():
    body = PAGE_HEAD + """
    <h1>VulnLab</h1>
    <p>A tiny, deliberately broken shop app for testing web app scanners against.</p>
    <ul>
      <li><a href="/products?id=1">/products?id=1</a> — product lookup, vulnerable to <b>SQL Injection</b></li>
      <li><a href="/profile?bio=hello+there">/profile?bio=hello+there</a> — bio preview, vulnerable to <b>Reflected XSS</b></li>
      <li><a href="/go?next=/products">/go?next=/products</a> — "continue to" link, vulnerable to <b>Open Redirect</b></li>
    </ul>
    </body></html>"""
    resp = make_response(body)
    # deliberately weak cookie: no Secure / HttpOnly / SameSite
    resp.set_cookie("vulnlab_session", "guest-0001")
    return resp


@app.route("/products")
def products():
    """SQL Injection — raw string concatenation into the query.
    Try: /products?id=1 or '1'='1
         /products?id=999 UNION SELECT 1,'x','x'
    """
    pid = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    try:
        # INTENTIONALLY VULNERABLE: never do this in real code.
        cur = conn.execute(f"SELECT id, name, price FROM products WHERE id = '{pid}'")
        rows = cur.fetchall()
        rows_html = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>" for r in rows)
        body = PAGE_HEAD + f"""
        <h1>Products</h1>
        <p>Looked up id = <code>{pid}</code></p>
        <table><tr><th>ID</th><th>Name</th><th>Price</th></tr>{rows_html}</table>
        </body></html>"""
    except Exception as e:
        # Deliberately leaky error message — this is what the scanner's
        # error-based SQLi check is looking for.
        body = PAGE_HEAD + f"<h1>Database error</h1><p>sql syntax error near: {e}</p></body></html>"
    finally:
        conn.close()
    return make_response(body)


@app.route("/profile")
def profile():
    """Reflected XSS — the bio param is echoed back unescaped."""
    bio = request.args.get("bio", "")
    body = PAGE_HEAD + f"""
    <h1>Profile preview</h1>
    <p>Your bio preview:</p>
    <div style="border:1px solid #ccc;padding:12px;border-radius:6px">{bio}</div>
    </body></html>"""
    return make_response(body)


@app.route("/go")
def go():
    """Open Redirect — next param is trusted blindly."""
    next_url = request.args.get("next", "/")
    return redirect(next_url, code=302)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5199))
    print(f"\n  VulnLab (intentionally vulnerable target) — http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port)
