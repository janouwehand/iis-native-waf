# SimpleWAF (IIS Native Module)

A minimal, defensive **IIS native WAF module** written in C++.

This project exists to block a specific class of malformed and abusive HTTP requests
*before* they reach ASP.NET, ASP.NET Core, or any application code.

It is **not** a full-featured Web Application Firewall.
It is intentionally small, fast, and opinionated.

---

## What this module does

The module runs at `RQ_BEGIN_REQUEST` and blocks requests that violate basic sanity rules.

Currently enforced rules:

- Block URLs longer than 16 KB
- Block raw non-ASCII bytes in the URL path
- Block `:` characters in the path (CRLF / header injection mitigation)
- Validate percent-encoding (`%XX`)
- Block requests made directly to an IP address instead of a hostname
- Log all blocked requests with timestamp, reason, and remote IP

Blocked requests receive:

- HTTP status: **400 Bad Request**
- IIS substatus codes (`400.1001+`) for diagnostics
- Zero-length response body

---

## Why this exists

- No budget or desire for a full commercial WAF
- IIS Request Filtering is too coarse for some cases
- Application-level validation happens too late
- Certain attacks should be rejected *before* routing, auth, or handlers
- Avoid scanning bots from cluttering the event log

This module is designed to be:
- predictable
- transparent
- boring
- hard to misconfigure

---

## What this is NOT

- ❌ Not a replacement for Cloudflare, Azure WAF, or ModSecurity
- ❌ Not a rule engine
- ❌ Not a regex-based filter
- ❌ Not aware of application semantics
- ❌ No learning, no heuristics, no magic

If you need those things, use a real WAF.

---

## Logging

Blocked requests are logged to a configurable file.

Example log entry:

````
[2025-01-02 14:33:21] [IP 203.0.113.45] [COLON_IN_PATH] /foo:bar
````

### Log path configuration

The log path is configured via an environment variable:

````
cmd setx SIMPLE_WAF_LOG_PATH "C:\inetpub\VBS\WAF.txt" /M
iisreset
````

If the variable is not set, the module falls back to:

````
C:\SimpleWAF.txt
````

## IIS Substatus Codes

| Substatus | Meaning |
|----------:|--------|
| 400.1001 | URL too long |
| 400.1002 | Raw non-ASCII character |
| 400.1003 | Colon in URL path |
| 400.1004 | Invalid percent encoding |
| 400.1005 | Direct IP access (host header) |

These appear in IIS logs and Failed Request Tracing.

---

## Performance considerations

- One pass over the URL path
- No heap allocations per request (except logging)
- No regex
- No parsing beyond basic byte inspection

In practice, overhead is negligible compared to ASP.NET request startup.

---

## Compatibility

- IIS 10+
- Windows Server 2016+
- Integrated pipeline
- All HTTP verbs (GET, POST, PUT, DELETE, etc.)

The module runs before routing and handlers.

---

## Security considerations

This module intentionally blocks:

- malformed requests
- ambiguous encodings
- non-standard URL forms

It may block:

- certain edge-case URLs
- poorly-behaved clients
- requests without a proper Host header

This is by design.

If your application legitimately requires Unicode paths or IP-based access,  
this module is probably not appropriate without modification.

---

## License

MIT License

See `LICENSE` for details.

---

## Disclaimer

This software is provided **as-is**, without warranty of any kind.

Use at your own risk.

If you deploy this in production, you are responsible for understanding  
what it blocks and why.
