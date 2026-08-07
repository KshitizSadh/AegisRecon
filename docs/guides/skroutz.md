# Skroutz Bug Bounty — Testing Guide (AegisRecon)

Program: **Skroutz S.A.** on Bugcrowd (private program).
This guide maps Skroutz's scope to concrete, **policy-compliant** AegisRecon
workflows and explicitly flags commands the program forbids.

> Only use this against a live program you are authorized to test. Stop and
> report anything involving real customer data immediately.

---

## 1. Program snapshot (condensed)

| | |
| --- | --- |
| In scope | `www.skroutz.gr` web app + associated API on **production** |
| Same-backend flavors (in scope) | `skroutz.gr`, `skroutz.de`, `skroutz.bg`, `skroutz.ro`, `skroutz.cy`, `skroutz.eu` |
| API docs | `https://developer.skroutz.gr/api/v3/` (OAuth2; test unauthenticated) |
| Rewards | P1 $4100–4500, P2 $1500–1750, P3 $600–850, P4 $100–250 |
| Stack | Ruby on Rails (+ Unicorn behind HAProxy), ReactJS frontend, WAF present |

The six flavor domains all serve the **same backend** — they are one target.
Treat every request as hitting live production with real data.

---

## 2. Hard guardrails — never run these

AegisRecon ships tools whose default behavior is **out of scope** for Skroutz.
Do not use them here.

| Forbidden action | AegisRecon command to avoid | Why |
| --- | --- | --- |
| IP / port scanning | `ports scan` / naabu | Program: "IP/port scanning" strictly prohibited |
| Attacking load balancers / hosts directly | `ports scan`, aggressive `probe` | "Attacking the load-balancers ... directly" prohibited |
| Broad subdomain enumeration | `recon run` crt.sh / subfinder | All subdomains are **out of scope**; only the listed hosts are authorized |
| Aggressive automated scanning | default `probe -threads 50`, default nuclei | "Excessive aggression on automated scanning tools" banned; WAF present |
| Default nuclei template sweep | `vuln run` (nuclei defaults) | Header/TLS/clickjacking/CSRF/error-message/rate-limit findings are all **out of scope** |
| Brute forcing credentials | — | "Do not attempt to brute force any credentials of any kind" |
| Mass account creation | — | "Do not create huge amounts of new database entries" |
| Completing payments | — | No test cards; submissions won't be refunded |

**Bottom line:** for this program, use AegisRecon for *evidence collection,
tracking, change detection and reporting* — not mass scanning.

---

## 3. Setup (scope-compliant)

Create a program and add each in-scope host as an **exact** rule.

> **Never use `--wildcard`.** That would authorize out-of-scope subdomains.

```bash
aegisrecon init
aegisrecon program create "Skroutz" --org "Skroutz S.A."

aegisrecon scope add Skroutz www.skroutz.gr
aegisrecon scope add Skroutz skroutz.gr
aegisrecon scope add Skroutz skroutz.de
aegisrecon scope add Skroutz skroutz.bg
aegisrecon scope add Skroutz skroutz.ro
aegisrecon scope add Skroutz skroutz.cy
aegisrecon scope add Skroutz skroutz.eu

aegisrecon scope list Skroutz
```

Notes:
- `scope add` validates bare hostnames — do **not** include `https://`.
- Exact rules do **not** cascade to subdomains (intended here).

### Seed assets without subdomain discovery

`recon run` does crt.sh/subfinder subdomain discovery — skip it. Instead
**ingest** the exact authorized hosts:

```bash
cat > hosts.txt <<'EOF'
www.skroutz.gr
skroutz.gr
skroutz.de
skroutz.bg
skroutz.ro
skroutz.cy
skroutz.eu
EOF

aegisrecon recon ingest Skroutz hosts.txt
```

This stores the 7 authorized hosts as assets and resolves DNS/IP scope-safely.

---

## 4. Safe automated phases

### 4.1 Fingerprinting (paced httpx)

`probe run` shells out to httpx. For a single production target keep the load
gentle (later `-threads` stays modest) and expect large pages:

```bash
aegisrecon probe run Skroutz
aegisrecon asset list Skroutz
```

Collects endpoints, status codes, titles, content types, web servers and
technologies for the in-scope hosts — clean evidence for reporting and manual
testing.

### 4.2 Client-side analysis (recommended)

Harvest the JS bundles, then scan them for secrets — a genuine, low-disruption
source of findings on a React frontend (OAuth `client_id` leak, API keys,
endpoint discovery):

```bash
aegisrecon harvest js Skroutz
aegisrecon secrets scan Skroutz
aegisrecon secrets list Skroutz
```

Scope-gating ensures `katana` only targets authorized hosts.

### 4.3 Change monitoring

Watch production for regressions/new endpoints with the snapshot/diff engine:

```bash
aegisrecon monitor run Skroutz
```

---

## 5. Manual playbooks mapped to focus areas

The program's focus areas are largely **manual** (auth, API, checkout, gift
cards, referrals, Skoop, 2FA). Use AegisRecon to capture and track what you
find.

### 5.1 Authentication & email verification
- Register through the normal flow (keep accounts to a minimum).
- Test **mandatory email verification** for new signups — does the verification
  check link/value-based token leak into responses / logs / predictable URLs?
- Test token reuse, and whether a verification link grants unintended state.
- **2FA is a priority focus** — it's only on specific endpoints/actions (not
  login; enabled for e.g. email changes). Hunt for 2FA bypasses there.

### 5.2 API v3 (unauthenticated)
- `developer.skroutz.gr/api/v3` is tested **without** `client_id`/`client_secret`.
- Enumerate endpoints and attempt authorization/authz bypasses.

### 5.3 Checkout / gift cards (do NOT complete payment)
- Walk the checkout/payment **steps** including credit-card steps — stop before
  submitting payment.
- **Skroutz Gift Cards are a standout risk** — treated as a product at checkout,
  then usable as a coupon on later orders. Test gift-card abuse (balance
  doubling, reusability, enumeration) without spending real money.

### 5.4 Plus + friend referrals (loyalty referral bonus)
- Abuse the referral scheme: self-referral, multi-account, coupon logic.

### 5.5 Skroutz Skoop (C2C marketplace)
- Focus on buyer-protection bypasses. Address/tax/MVN validation gaps are
  **intentionally out of scope**.

---

## 6. Tracking & reporting

Log and triage findings through the same pipeline:

```bash
aegisrecon finding list Skroutz
aegisrecon finding set-status <finding-id> triaged   # triage as you work
```

Generate a clean evidence package for the Bugcrowd submission:

```bash
aegisrecon report json Skroutz --title "Skroutz engagement"
aegisrecon report markdown Skroutz

# Offline dashboard to review everything before you write up:
aegisrecon report dashboard Skroutz
# or serve the REST API + dashboard:
aegisrecon api serve --host 127.0.0.1 --port 8000
```

Suggestions for manual testing, computed from your assets/findings:

```bash
aegisrecon suggest run Skroutz
aegisrecon suggest run Skroutz --category api
aegisrecon suggest run Skroutz --category secrets
```

---

## 7. Troubleshooting: `httpx command failed`

A classic gotcha: AegisRecon's optional **`[api]` extra** installs the *Python*
`httpx` library, whose CLI entry point can **shadow** ProjectDiscovery's Go
`httpx` binary on `PATH`. Symptom: `probe run` fails with
```text
The httpx command line client could not run because the required dependencies
were not installed...  pip install 'httpx[cli]'
```

AegisRecon now detects and skips that Python stub and keeps scanning `PATH`
for the real Go binary. Shortest fix — install the Go binaries and prefer them:

```bash
aegisrecon tools install                            # fetches httpx, katana, dnsx, ...
export PATH="$HOME/go/bin:$PATH"                     # ensure Go bin precedes the venv
file "$(which httpx)"                               # should be a Go (ELF) binary
```

Use `aegisrecon tools list` to see which binaries are present/missing.