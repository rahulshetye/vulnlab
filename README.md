# VulnLab — practice target for VulnScan Pro

A tiny, deliberately broken Flask app with three GET-param endpoints, each
carrying a different severity, so a scan against it produces a realistic
spread of findings:

| Endpoint | Example URL | Vulnerability | Expected severity |
|---|---|---|---|
| `/products` | `/products?id=1` | SQL Injection (string concat into a raw query, error messages leak DB errors) | **HIGH / CRITICAL** |
| `/profile` | `/profile?bio=hello` | Reflected XSS (bio echoed back unescaped) | **MEDIUM / HIGH** |
| `/go` | `/go?next=/products` | Open Redirect (next param trusted blindly) | **LOW / MEDIUM** |

It also deliberately has no security headers and sets a cookie without
`Secure` / `HttpOnly` / `SameSite`, so VulnScan Pro's Headers and Cookies
modules will report findings too.

## ⚠️ Important

Every bug here is intentional, for testing your own scanner against your
own throwaway deployment. Do not:
- deploy this with real data or reuse the code in a real project
- leave it running somewhere a stranger could stumble onto it and actually exploit it
- point VulnScan Pro (or any scanner) at anyone else's site — only this one, which you own

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

Opens on `http://localhost:5199`.

## Deploy (so VulnScan Pro — which itself has to refuse localhost/private IPs — has a real public URL to hit)

### Option A: Render (free tier, easiest)
1. Push this folder to a GitHub repo.
2. On [render.com](https://render.com) → New → Web Service → connect the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Deploy. Render gives you a `https://your-app.onrender.com` URL.

### Option B: Railway
1. Push this folder to a GitHub repo.
2. On [railway.app](https://railway.app) → New Project → Deploy from GitHub repo.
3. Railway auto-detects the `Procfile` and deploys. It gives you a public URL.

### Option C: ngrok (quick, temporary, no deploy needed)
If you just want a public URL for a few minutes without deploying anywhere:
```bash
python app.py
ngrok http 5199
```
Use the `https://xxxx.ngrok-free.dev` URL ngrok gives you as your scan target.
(Free ngrok shows an interstitial warning page on the first hit from a
non-browser client — if your scan results look flat/identical across all
payloads, that's usually why. A real deploy via Render/Railway avoids this.)

## Scanning it with VulnScan Pro

Try these as targets in VulnScan Pro (swap in your deployed domain):

```
https://your-app.onrender.com/products?id=1
https://your-app.onrender.com/profile?bio=hello
https://your-app.onrender.com/go?next=/products
```

Running all three in one scan session gives you one HIGH/CRITICAL finding,
one MEDIUM/HIGH finding, one LOW/MEDIUM finding, plus the missing-header
and weak-cookie findings — a good spread for a demo.
