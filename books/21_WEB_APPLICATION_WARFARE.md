# Chapter 21 — Web Application Warfare: OWASP and Beyond

**VADER-RCE Field Manual**
**Prerequisite**: Volumes I-IV, Ch 17 (Network Warfare)
**Drill**: DRILLS/21_web_app/

---

## Why Web Applications

Everything runs on the web now. Banks, hospitals, defense contractors, Microsoft's
own portals — all web apps. The OWASP Top 10 has barely changed in a decade because
developers keep making the same mistakes. Different language, same bugs.

You learned memory corruption in Volumes I-III. Web app bugs are LOGIC corruption —
the application does something the developer didn't intend because input validation
is missing, broken, or bypassable.

The skill transfer from your mpengine work is direct: you learned to study a parser,
understand its assumptions, and violate them. A web app is just a parser that speaks
HTTP instead of binary file formats. The methodology is identical.

For bug bounties, web apps are the highest-volume payout category. Microsoft, Google,
Facebook — they all run bounty programs. Most payouts are for web vulns, not memory
corruption. This is the accessible attack surface.

---

## Web Architecture — The Kill Chain

Before you attack a web app, understand how the request flows:

```
Browser -> DNS -> Load Balancer -> Web Server -> App Server -> Database
                                      |              |           |
                                   Static        Business     Stored
                                   Files         Logic        Data
                                      |              |           |
                                Response <- Template <- Query Result
```

Every arrow is an attack surface:
- **Browser to Server**: manipulate HTTP headers, cookies, parameters
- **Server to App**: path traversal, SSRF, header injection
- **App to Database**: SQL injection, NoSQL injection, LDAP injection
- **App to Template**: server-side template injection (SSTI)
- **App to Filesystem**: local/remote file inclusion, arbitrary file read/write
- **Response to Browser**: XSS, open redirect, clickjacking

### HTTP Protocol — The Language of Web War

Every web request is text:

```
GET /api/user/1337 HTTP/1.1
Host: target.com
Cookie: session=abc123def456
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json
```

Every field is attacker-controlled. The server trusts that `Host:` is legitimate,
that the `Cookie` belongs to the authenticated user, that `Content-Type` matches
the actual body. Every trust assumption is testable.

**Methods that matter**:
- `GET` — retrieve data (parameters in URL, cached, logged)
- `POST` — submit data (parameters in body, not cached)
- `PUT/PATCH` — update resources (often improperly authorized)
- `DELETE` — remove resources (if the server actually checks who's asking)
- `OPTIONS` — CORS preflight (reveals allowed methods and origins)

**Headers that leak information**:
- `Server: Apache/2.4.49` — exact version = CVE lookup
- `X-Powered-By: PHP/8.1.2` — technology stack exposed
- `X-Debug-Token` — debug mode left on in production

---

## SQL Injection — The Immortal Bug

Twenty-five years after its discovery, SQLi is still in the OWASP Top 10. Still
being found in production. Still paying bounties.

### How It Works

The app builds a SQL query by concatenating user input:

```python
# VULNERABLE -- user input directly in query string
query = "SELECT * FROM users WHERE id = " + request.args['id']
cursor.execute(query)
```

Normal input: `id=5` produces `SELECT * FROM users WHERE id = 5`

Attack input: `id=5 OR 1=1` produces `SELECT * FROM users WHERE id = 5 OR 1=1`

That returns EVERY user. The input changed the query's LOGIC.

### SQLi Types

**Union-Based** — Extract data from other tables:
```
id=5 UNION SELECT username, password FROM admins--
```
The `UNION` appends a second query's results. The `--` comments out the rest.
You need to match column count and types. Use `ORDER BY N` to find column count.

**Error-Based** — Force the database to leak data through error messages:
```
id=5 AND 1=CONVERT(int, (SELECT TOP 1 password FROM admins))
```
The type conversion fails and the error message contains the password value.

**Blind Boolean** — No visible output, but different responses for true/false:
```
id=5 AND SUBSTRING((SELECT password FROM admins LIMIT 1),1,1)='a'
```
If the page loads normally then the first character is 'a'. If different, not 'a'.
Iterate through every character. Slow but works when nothing else does.

**Blind Time-Based** — No output difference at all, so use response timing:
```
id=5; IF (SUBSTRING(password,1,1)='a') WAITFOR DELAY '0:0:5'--
```
If response takes 5 seconds, character is 'a'. Extremely slow. Last resort.

**Second-Order** — Input stored safely, but used unsafely later:
```
Register username: admin'--
Later the stored value is used in a different unsanitized query
```
The injection triggers when the stored value is consumed by a different code path.

### WAF Bypass Techniques

Web Application Firewalls block obvious payloads. Bypass methods:

| Technique | Example | Why It Works |
|-----------|---------|-------------|
| Case mixing | `SeLeCt` | WAF pattern matches exact case |
| Comment injection | `SEL/**/ECT` | SQL ignores inline comments |
| URL encoding | `%53%45%4C%45%43%54` | Double-encoding bypasses single decode |
| Whitespace alternatives | Tab/newline instead of spaces | Parser accepts them, WAF doesn't |
| Equivalent functions | `CHAR(65)` instead of `'A'` | Avoids string literal detection |

### Prevention (Know What You're Bypassing)

Parameterized queries make SQLi impossible:
```python
# SAFE -- parameterized query, input is DATA not CODE
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
The database treats the parameter as a literal value, never as SQL syntax.
When you find SQLi in 2026, it means someone concatenated strings instead.

---

## Cross-Site Scripting (XSS) — Injecting Into The Browser

SQLi attacks the server. XSS attacks other USERS through the server.

### The Three Types

**Reflected XSS** — payload in URL, reflected in response. Victim clicks the
crafted link, their browser executes attacker's script, session data exfiltrated.

**Stored XSS** — payload saved in database, served to every visitor. Far more
dangerous because every user who views the page runs the attacker's code.
Common in comment fields, profile descriptions, message boards.

**DOM-Based XSS** — payload never touches the server:
```javascript
// Vulnerable client-side code reads from location.hash
// and writes directly to innerHTML without sanitization
document.getElementById('output').innerHTML = location.hash.substring(1);
```
The browser itself parses the attacker's input into the DOM.

### Payload Construction

Basic test (proof of concept):
```html
<script>alert(document.domain)</script>
```

When `<script>` is filtered — use event handlers:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

When angle brackets are filtered — inject into existing attributes:
```
" onfocus="alert(1)" autofocus="
```

### CSP Bypass

Content Security Policy restricts where scripts can load from:
```
Content-Security-Policy: script-src 'self' https://cdn.example.com
```

Bypass methods:
- Find a JSONP endpoint on an allowed domain
- Angular/React template injection if the framework is on an allowed CDN
- Base tag injection to redirect relative script URLs
- `script-src 'unsafe-inline'` — CSP is useless if this is set

### XSS Impact

Cookie theft is just the beginning:
- **Session hijacking**: steal session token, impersonate user
- **Keylogging**: inject a keylogger into the page
- **Phishing**: replace the page content with a fake login form
- **Worm**: self-propagating XSS that spreads to every visitor
- **Crypto mining**: use victim's CPU without consent

---

## Server-Side Request Forgery (SSRF)

Make the SERVER send requests on YOUR behalf. The server is inside the network —
it can reach things you can't.

### The Classic Attack

Application fetches a URL you provide:
```
POST /api/fetch-preview
{"url": "https://legitimate-site.com/article"}
```

Attack — request internal resources:
```
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

That's the AWS metadata endpoint. Returns temporary IAM credentials. From the
outside you can't reach it. But the server CAN — it's running inside AWS.

### Cloud Metadata Endpoints

| Cloud | Endpoint | What You Get |
|-------|----------|-------------|
| AWS | `169.254.169.254/latest/meta-data/` | IAM creds, instance role, VPC config |
| GCP | `metadata.google.internal/computeMetadata/v1/` | Service account tokens |
| Azure | `169.254.169.254/metadata/instance` | Managed identity tokens |

One SSRF in a cloud app = potential full cloud account takeover.

### Internal Network Discovery

Use SSRF to port scan the internal network — the server becomes your proxy.
Try internal IPs (10.x, 172.16.x, 192.168.x), localhost on various ports,
internal service names. Fast response = port open. Timeout = closed.

### Blind SSRF

Server doesn't return the response to you. Use:
- **Timing**: response time reveals whether internal port is open
- **Out-of-band**: point the SSRF at your controlled server, check access logs

---

## Authentication and Session Attacks

### JWT Vulnerabilities

JSON Web Tokens — stateless authentication. Three common flaws:

**Algorithm None attack**: Set header to `{"alg": "none"}` and strip the
signature. If the server accepts it, you forge any token without the secret.

**Weak secret**: Crack with hashcat (`-m 16500`). If the secret is in a
wordlist, you forge any token.

**Key confusion** (RS256 to HS256): Server expects RS256 (asymmetric, public key
verifies). Attacker sends HS256 (symmetric, same key signs AND verifies). Sign
the token with the PUBLIC key using HS256. Server uses public key to verify — 
it matches. Token forged using public information.

### Session Attacks

- **Fixation**: set victim's session ID before they log in, then you know it
- **Prediction**: session IDs based on timestamp or counter are predictable
- **Hijacking**: steal session via XSS, network sniffing, or Referer leakage

### Password Reset Flaws

- Token in URL leaked via Referer header to third-party sites
- Token = MD5(email + timestamp) is predictable
- Token reuse: previous valid tokens accepted forever
- Host header injection: reset link points to attacker's domain

---

## Insecure Deserialization

Serialization converts objects to bytes. Deserialization reverses it. If the
application deserializes untrusted data, the attacker controls what objects are
created — including objects that execute code during reconstruction.

### Why It's Dangerous

In most languages, deserialization can trigger constructor/destructor execution,
magic method calls, callback execution, and property access with side effects.
The object comes to life as it's reconstituted — and if the attacker controls
the blueprint, they control what it does when it wakes up.

### Language-Specific Risks

**Java**: `ObjectInputStream.readObject()` on untrusted input = arbitrary code
execution. Tool: ysoserial generates payloads for dozens of gadget chains.
Common targets: Apache Commons Collections, Spring Framework.

**Python**: `pickle.loads()` on untrusted input = arbitrary code execution.
By design. The pickle protocol can invoke any callable. The documentation warns
against it. Developers use it anyway.

**.NET**: `BinaryFormatter.Deserialize()` on untrusted input = same result.
Microsoft deprecated BinaryFormatter in .NET 8. Still found in legacy apps.

### Detection

Look for Base64-encoded blobs in cookies, hidden fields, API parameters.
Java serialized objects start with `AC ED 00 05` (hex) or `rO0AB` (base64).
Python pickle has specific protocol headers. Recognize these signatures.

---

## File Upload Attacks

Application accepts file uploads. The goal: get server-side executable content
into a web-accessible directory so the server executes it when requested.

### Extension Bypass Techniques

| Filter | Bypass | Why |
|--------|--------|-----|
| Blacklist blocks common extensions | Try alternate extensions for same language | Incomplete blacklist |
| Whitelist allows only images | Null byte in old servers truncates filename | Parser disagreement |
| Content-Type check | Set header to image type, body contains code | Server trusts header |
| Magic bytes check | Prepend valid image header bytes to code | Only first bytes checked |
| Double extension | `file.code.jpg` served through wrong handler | Server misconfiguration |

### Image Polyglots

Create a file that is simultaneously a valid image AND valid code. The file passes
image validation (valid header, correct structure) but the web server executes the
embedded code if served through the wrong handler. Possible because image formats
tolerate extra data after the required structure.

### Directory Traversal via Filename

```
filename="../../../etc/cron.d/task"
```
If the app doesn't sanitize the filename, you write to arbitrary paths.
Combined with a scheduled task payload = persistent code execution.

### Prevention (Know What Stops You)

- Uploads stored outside the web root (can't request them via URL)
- Files renamed to random UUIDs (no user-controlled names)
- Content validated, not just extension or Content-Type
- Separate domain for serving uploads with no script execution

---

## API Security

Modern apps are APIs. The frontend is a thin client; all logic is server-side.

### BOLA / IDOR — The Number One API Vulnerability

The app checks IF you're authenticated but not WHAT you're authorized to access:

```
GET /api/users/1337/profile   -> Your profile (authorized)
GET /api/users/1338/profile   -> Someone else's profile (also works)
```

Just increment the ID. If it returns data, that's a vulnerability. Trivial to
find, trivial to exploit, impacts every user in the database.

### Mass Assignment

API accepts more parameters than intended:
```json
POST /api/users/update
{"name": "attacker", "role": "admin"}
```
If the backend binds ALL request parameters to the user object without filtering,
you just escalated yourself. Common in Rails, Django, Express.

### GraphQL Specific

**Introspection** — ask the API to describe itself:
```graphql
{__schema{types{name,fields{name,type{name}}}}}
```
Returns every type, field, and relationship. Full API map in one query.

**Nested query attacks**: exponential server load via deeply nested relationships.
**Batch attacks**: 1000 login attempts in one request, bypassing rate limiting.

---

## Bug Bounty Methodology

### Phase 1: Reconnaissance

```
Subdomain enum:  subfinder -d target.com | httpx
Tech stack:      whatweb https://target.com
JS file mining:  gau target.com | grep '\.js$' | sort -u
Parameter enum:  paramspider -d target.com
Wayback Machine: waybackurls target.com | sort -u
```

### Phase 2: Prioritize

1. **Authentication flows** — login, register, password reset, OAuth
2. **File operations** — upload, download, import/export
3. **Search/filter** — often reflects input (XSS) or builds queries (SQLi)
4. **API endpoints** — CRUD operations on user data (IDOR)
5. **Payment/billing** — business logic flaws, race conditions
6. **Admin panels** — probe for auth bypass even if you can't access them

### Phase 3: Chain Low Findings Into High Impact

Individual low-severity bugs combined into high-severity chains:
- Self-XSS + CSRF = Stored XSS (victim visits attacker page, XSS fires in their session)
- Open Redirect + OAuth = Account Takeover (redirect auth code to attacker)
- SSRF + Cloud Metadata = Full AWS Compromise
- IDOR + PII = Data Breach (escalate from "view profile" to "dump all users")

The chain is often more valuable than any individual finding.

### Report Writing

**Structure**:
```
Title: [Type] -- [Impact] via [Vector] on [Endpoint]
Severity: Critical/High/Medium/Low (with CVSS)
Endpoint: https://target.com/api/vulnerable-endpoint
Parameter: id

## Summary
One paragraph. What's broken and what an attacker can do.

## Steps to Reproduce
1. Navigate to X
2. Intercept with Burp
3. Modify parameter Y to Z
4. Observe: [unexpected behavior]

## Impact
What can an attacker actually do? Quantify: "affects all N users"

## Remediation
Specific fix. Code example if possible.

## Proof of Concept
Screenshots, HTTP requests/responses, video.
```

---

## Tools of The Trade

| Category | Tool | Purpose |
|----------|------|---------|
| Proxy | Burp Suite | Intercept/modify HTTP traffic |
| Scanner | Nuclei | Template-based vuln scanning |
| Fuzzer | ffuf | Directory/parameter brute force |
| SQLi | sqlmap | Automated SQL injection |
| XSS | Dalfox | XSS scanner with WAF bypass |
| Recon | subfinder + httpx | Subdomain enum + alive check |
| Crawl | katana | JS-aware web crawler |
| Wordlists | SecLists | Industry-standard fuzzing lists |

### Burp Suite — Your Primary Weapon

Learn Burp like you learned WinDbg. It's the core tool:
- **Proxy**: intercept every request between browser and server
- **Repeater**: modify and resend individual requests
- **Intruder**: automated parameter fuzzing
- **Scanner**: automated vuln scanning (Pro only)
- **Decoder**: encode/decode payloads
- **Comparer**: diff two responses to find blind injection signals

---

## Mapping To The Doctrine

The 0x1security principle from Ch 13 applies directly:

**See paths**: HTTP request flows through server processing to database to response.
Every step is a parser. Every parser has assumptions. Violate the assumptions.

**See blocks**: WAFs, CSP, CORS, input validation, parameterized queries.
These are the defenses. Map them before you attack.

**Find substitutes**: WAF blocks `<script>`? Use event handlers. CSP blocks
inline scripts? Find a JSONP endpoint. SQLi filter blocks `UNION`? Use blind
techniques. There's always another path.

---

## Key Terms

| Term | Definition |
|------|-----------|
| SQLi | SQL Injection — injecting SQL syntax through user input |
| XSS | Cross-Site Scripting — injecting client-side code via the server |
| SSRF | Server-Side Request Forgery — making the server send requests for you |
| CSRF | Cross-Site Request Forgery — tricking victim's browser into sending requests |
| IDOR | Insecure Direct Object Reference — accessing other users' data by ID |
| BOLA | Broken Object-Level Authorization — same as IDOR, OWASP API term |
| CSP | Content Security Policy — browser-enforced script loading restrictions |
| CORS | Cross-Origin Resource Sharing — browser-enforced origin restrictions |
| JWT | JSON Web Token — stateless authentication token |
| WAF | Web Application Firewall — HTTP-layer attack filter |

---

## Drill 21 — Web Application Warfare

**Exercise A**: Set up DVWA or use PortSwigger Web Academy. Complete at least
one lab in each category: SQLi, XSS, SSRF.

**Exercise B**: Find and chain two low-severity bugs in a practice app into a
single high-severity exploit. Document the chain with Burp screenshots.

**Exercise C**: Write a bug bounty report for a practice finding using the
template above. Have someone else reproduce from your report alone.

**Exercise D**: Set up Burp Suite, configure browser proxy, intercept a login
request. Identify every parameter, header, and cookie. For each one, describe
what modification would test for a vulnerability.

---

## Summary — Key Takeaways

- Web apps are logic parsers that speak HTTP. Same methodology as binary parsing — understand assumptions, violate them.
- SQLi is 25 years old and still paying bounties. Parameterized queries prevent it. Concatenation causes it.
- XSS attacks USERS through the application. Stored XSS hits every visitor.
- SSRF turns the server into your proxy. In cloud environments, metadata endpoints = credential theft.
- JWT flaws (none algorithm, weak secret, key confusion) = authentication bypass.
- Deserialization of untrusted data = arbitrary code execution. By design. Java, Python, .NET.
- File upload attacks bypass extension/content filters to get executable content on the server.
- IDOR/BOLA is the number one API vulnerability. Just change the ID.
- Bug chaining: two medium findings combined often equal one critical. Think in chains.
- Burp Suite is to web hacking what WinDbg is to memory corruption. Master it.

**Next**: Ch 22 — OSINT and Social Engineering — completing the kill chain from technical exploitation to the human factor.
