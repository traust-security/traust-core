# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from types import MappingProxyType

from traust_core.v1.models.findings import CweReference

# Curated crosswalk migrated from Apache-2.0 Traust main 60dc9316.
# MITRE CWE names; ASVS mappings and fixes are Traust guidance, not official MITRE/OWASP mappings.
# The migrated table's Apache-2.0 license is retained in cwe-reference-LICENSE.txt.
SOURCE = "traust:harnessing/insecure-patterns/scripts/build_insecure_patterns.py@60dc9316"
ASVS_SOURCE = "https://github.com/OWASP/ASVS/tree/v5.0.0/5.0"
CWE_SOURCE = "https://cwe.mitre.org/"

_DATA = {
    "CWE-532": (
        "Insertion of Sensitive Information into Log File",
        "V16.2",
        "Security Logging \u203a General Logging",
        "Redact tokens, credentials, presigned URLs and full request/response bodies "
        "before logging; log identifiers and hashes, never secret material.",
    ),
    "CWE-200": (
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "V14.2",
        "Data Protection \u203a General Data Protection",
        "Return minimal fields; strip stack traces, internal hostnames and object dumps "
        "from responses and errors surfaced to callers.",
    ),
    "CWE-209": (
        "Generation of Error Message Containing Sensitive Information",
        "V16.5",
        "Security Logging \u203a Error Handling",
        "Map internal errors to generic user-facing messages; log detail server-side only.",
    ),
    "CWE-214": (
        "Invocation of Process Using Visible Sensitive Information",
        "V13.3",
        "Configuration \u203a Secret Management",
        "Pass secrets via env or stdin, never argv; scrub `/proc/<pid>/cmdline`-visible flags.",
    ),
    "CWE-312": (
        "Cleartext Storage of Sensitive Information",
        "V14.2",
        "Data Protection \u203a General Data Protection",
        "Encrypt at rest or store a reference to a secrets manager instead of the "
        "plaintext value; set restrictive file modes.",
    ),
    "CWE-313": (
        "Cleartext Storage in a File or on Disk",
        "V14.2",
        "Data Protection \u203a General Data Protection",
        "Write secrets only to tmpfs/Secret volumes with 0600 perms, or don't write them "
        "at all — read from the secret store on demand.",
    ),
    "CWE-315": (
        "Cleartext Storage of Sensitive Information in a Cookie",
        "V3.3",
        "Web Frontend \u203a Cookie Setup",
        "Store only an opaque session id in the cookie; keep sensitive state server-side, "
        "set HttpOnly+Secure.",
    ),
    "CWE-522": (
        "Insufficiently Protected Credentials",
        "V13.3",
        "Configuration \u203a Secret Management",
        "Load credentials from a mounted Secret / vault at runtime; never embed in "
        "source, image layers, or ConfigMaps.",
    ),
    "CWE-798": (
        "Use of Hard-coded Credentials",
        "V13.3",
        "Configuration \u203a Secret Management",
        "Remove the literal; inject via Secret/env at deploy time and rotate the exposed value.",
    ),
    "CWE-256": (
        "Plaintext Storage of a Password",
        "V13.3",
        "Configuration \u203a Secret Management",
        "Store only a salted hash (argon2id/bcrypt) or a reference to an external secret store.",
    ),
    "CWE-359": (
        "Exposure of Private Personal Information",
        "V14.2",
        "Data Protection \u203a General Data Protection",
        "Mask or tokenise PII before logging/returning; enforce field-level access control.",
    ),
    "CWE-526": (
        "Cleartext Storage of Sensitive Information in an Environment Variable",
        "V13.3",
        "Configuration \u203a Secret Management",
        "Don't `os.Setenv`/`export` secrets for child processes; pass them on stdin or "
        "via a scoped file descriptor and unset immediately after use.",
    ),
    "CWE-215": (
        "Insertion of Sensitive Information Into Debugging Code",
        "V13.4",
        "Configuration \u203a Unintended Information Leakage",
        "Gate `Development:true`/debug loggers behind a build tag or env flag that "
        "defaults off in release builds.",
    ),
    "CWE-1059": (
        "Insufficient Technical Documentation",
        "V15.1",
        "Secure Coding & Architecture \u203a Documentation",
        "Add SECURITY.md, dependency-update automation, and release provenance; wire "
        "OpenSSF Scorecard into CI.",
    ),
    "CWE-497": (
        "Exposure of System Data to an Unauthorized Control Sphere",
        "V13.4",
        "Configuration \u203a Unintended Information Leakage",
        "Suppress build metadata, env dumps and internal paths from externally reachable "
        "endpoints.",
    ),
    "CWE-548": (
        "Exposure of Information Through Directory Listing",
        "V13.4",
        "Configuration \u203a Unintended Information Leakage",
        "Disable autoindex/directory listing; serve only explicitly routed paths.",
    ),
    "CWE-306": (
        "Missing Authentication for Critical Function",
        "V6.3",
        "Authentication \u203a General Authentication Security",
        "Put the handler behind the auth middleware / require a verified identity before "
        "executing the action; deny by default.",
    ),
    "CWE-287": (
        "Improper Authentication",
        "V6.3",
        "Authentication \u203a General Authentication Security",
        "Verify credential *and* bind result to the session; don't trust caller-supplied "
        "identity fields.",
    ),
    "CWE-862": (
        "Missing Authorization",
        "V8.3",
        "Authorization \u203a Operation Level Authorization",
        "Add an explicit permission check that ties the *object* being acted on to the "
        "caller's identity/role.",
    ),
    "CWE-863": (
        "Incorrect Authorization",
        "V8.3",
        "Authorization \u203a Operation Level Authorization",
        "Re-derive the resource owner server-side and compare to the authenticated "
        "principal; never trust client-sent owner/tenant IDs.",
    ),
    "CWE-639": (
        "Authorization Bypass Through User-Controlled Key (IDOR)",
        "V8.2",
        "Authorization \u203a General Authorization Design",
        "Scope every lookup by the caller's tenant/owner in the query itself, not just "
        "the response filter.",
    ),
    "CWE-269": (
        "Improper Privilege Management",
        "V8.2",
        "Authorization \u203a General Authorization Design",
        "Run with the minimum role/UID needed; drop capabilities immediately after the "
        "privileged step.",
    ),
    "CWE-250": (
        "Execution with Unnecessary Privileges",
        "V8.2",
        "Authorization \u203a General Authorization Design",
        "Remove `privileged`/root; request only the specific Linux capability or K8s RBAC "
        "verb the code path needs.",
    ),
    "CWE-284": (
        "Improper Access Control",
        "V8.2",
        "Authorization \u203a General Authorization Design",
        "Default-deny; enumerate the exact principals allowed and enforce at the entry "
        "point, not deep in the call stack.",
    ),
    "CWE-285": (
        "Improper Authorization",
        "V8.3",
        "Authorization \u203a Operation Level Authorization",
        "Centralise the authz decision in one function and call it from every handler; "
        "add tests per role\u00d7operation.",
    ),
    "CWE-613": (
        "Insufficient Session Expiration",
        "V7.3",
        "Session Management \u203a Session Timeout",
        "Set absolute + idle timeouts and invalidate the server-side session record on logout.",
    ),
    "CWE-384": (
        "Session Fixation",
        "V7.2",
        "Session Management \u203a Fundamental Session Management Security",
        "Regenerate the session identifier on every privilege change (login, sudo, impersonate).",
    ),
    "CWE-346": (
        "Origin Validation Error",
        "V3.5",
        "Web Frontend \u203a Browser Origin Separation",
        "Validate `Origin`/`Referer` against an allow-list before honouring "
        "state-changing requests or WebSocket upgrades.",
    ),
    "CWE-352": (
        "Cross-Site Request Forgery (CSRF)",
        "V3.5",
        "Web Frontend \u203a Browser Origin Separation",
        "Require a per-session anti-CSRF token (or SameSite=Strict cookies) on every "
        "state-changing route.",
    ),
    "CWE-290": (
        "Authentication Bypass by Spoofing",
        "V6.3",
        "Authentication \u203a General Authentication Security",
        "Don't derive identity from spoofable inputs (Host header, X-Forwarded-*, client "
        "IP); authenticate the actual credential.",
    ),
    "CWE-303": (
        "Incorrect Implementation of Authentication Algorithm",
        "V6.3",
        "Authentication \u203a General Authentication Security",
        "Use the framework's authenticator; delete the bespoke comparison / token-parsing code.",
    ),
    "CWE-288": (
        "Authentication Bypass Using an Alternate Path",
        "V6.3",
        "Authentication \u203a General Authentication Security",
        "Register auth middleware on the router, not per-route; block direct access to "
        "internal handlers.",
    ),
    "CWE-1390": (
        "Weak Authentication",
        "V6.3",
        "Authentication \u203a General Authentication Security",
        "Replace static/shared tokens with per-principal, time-bound credentials.",
    ),
    "CWE-295": (
        "Improper Certificate Validation",
        "V12.3",
        "Secure Communication \u203a Service-to-Service",
        "Delete `InsecureSkipVerify`/`verify=False`; load the CA bundle for the target "
        "and pin/hostname-verify.",
    ),
    "CWE-319": (
        "Cleartext Transmission of Sensitive Information",
        "V12.2",
        "Secure Communication \u203a HTTPS with External Services",
        "Require TLS on the client (`https://`, `sslmode=require`) and refuse to fall "
        "back to plaintext.",
    ),
    "CWE-297": (
        "Improper Validation of Certificate with Host Mismatch",
        "V12.3",
        "Secure Communication \u203a Service-to-Service",
        "Leave `ServerName`/SNI at its default so the library checks it against the cert "
        'SAN; don\'t override to `""`.',
    ),
    "CWE-326": (
        "Inadequate Encryption Strength",
        "V11.3",
        "Cryptography \u203a Encryption Algorithms",
        "Raise key sizes to current minima (RSA-2048/AES-256/TLS1.2+) and disable legacy "
        "cipher suites.",
    ),
    "CWE-757": (
        "Selection of Less-Secure Algorithm During Negotiation",
        "V12.1",
        "Secure Communication \u203a General TLS Guidance",
        "Set `MinVersion: TLS1.2` and an explicit cipher-suite allow-list; reject downgrade.",
    ),
    "CWE-327": (
        "Use of a Broken or Risky Cryptographic Algorithm",
        "V11.3",
        "Cryptography \u203a Encryption Algorithms",
        "Swap MD5/SHA1/DES/RC4 for SHA-256/AES-GCM/ChaCha20-Poly1305; use a vetted "
        "library primitive.",
    ),
    "CWE-328": (
        "Use of Weak Hash",
        "V11.4",
        "Cryptography \u203a Hashing and Hash-based Functions",
        "Use SHA-256+ for integrity and argon2id/bcrypt for passwords.",
    ),
    "CWE-330": (
        "Use of Insufficiently Random Values",
        "V11.5",
        "Cryptography \u203a Random Values",
        "Use `crypto/rand` (Go), `secrets` (Py), `crypto.randomBytes` (Node) — never "
        "`math/rand`/`random` for security decisions.",
    ),
    "CWE-338": (
        "Use of Cryptographically Weak PRNG",
        "V11.5",
        "Cryptography \u203a Random Values",
        "Replace `math/rand`/`Math.random()` with the platform CSPRNG when the value "
        "guards access.",
    ),
    "CWE-321": (
        "Use of Hard-coded Cryptographic Key",
        "V11.2",
        "Cryptography \u203a Secure Cryptography Implementation",
        "Load the key from a Secret/KMS at runtime; rotate the exposed key.",
    ),
    "CWE-347": (
        "Improper Verification of Cryptographic Signature",
        "V9.1",
        "Self-contained Tokens \u203a Source and Integrity",
        "Verify the signature *before* using any claim; pin the expected algorithm and key-id.",
    ),
    "CWE-916": (
        "Use of Password Hash With Insufficient Computational Effort",
        "V11.4",
        "Cryptography \u203a Hashing and Hash-based Functions",
        "Hash passwords with argon2id/bcrypt/scrypt, not raw SHA-*.",
    ),
    "CWE-323": (
        "Reusing a Nonce/Key Pair in Encryption",
        "V11.3",
        "Cryptography \u203a Encryption Algorithms",
        "Generate a fresh random nonce per message; never derive it from a counter you "
        "don't persist.",
    ),
    "CWE-331": (
        "Insufficient Entropy",
        "V11.5",
        "Cryptography \u203a Random Values",
        "Seed from the OS CSPRNG; make identifiers ≥128 bits.",
    ),
    "CWE-1240": (
        "Use of a Cryptographic Primitive with a Risky Implementation",
        "V11.2",
        "Cryptography \u203a Secure Cryptography Implementation",
        "Delete the hand-rolled crypto; call the stdlib/BoringSSL/`cryptography` "
        "primitive instead.",
    ),
    "CWE-78": (
        "OS Command Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Drop `shell=True`/`sh -c`; call the binary with an argv slice and validate each "
        "element against an allow-list.",
    ),
    "CWE-77": (
        "Command Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Build the command as a fixed argv array; never interpolate untrusted data into a "
        "single command string.",
    ),
    "CWE-88": (
        "Argument Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Prefix user-derived args with `--` and reject values that start with `-`; prefer "
        "library APIs over CLI shell-outs.",
    ),
    "CWE-89": (
        "SQL Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Use parameterised queries / the ORM's bind API; never concatenate identifiers or "
        "values into SQL.",
    ),
    "CWE-79": (
        "Cross-site Scripting (XSS)",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Context-encode at the sink (HTML/attr/JS/URL) or render via a framework that "
        "auto-escapes; ban `innerHTML`/`v-html` on untrusted data.",
    ),
    "CWE-74": (
        "Injection (generic)",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Separate code from data: use parameterised APIs and encode for the target interpreter.",
    ),
    "CWE-94": (
        "Code Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Remove `eval`/`exec`/`Function()` on external input; map input→action via a lookup table.",
    ),
    "CWE-90": (
        "LDAP Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Escape filter metacharacters via the LDAP library's escape function before "
        "building the filter string.",
    ),
    "CWE-91": (
        "XML Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Build XML with a DOM/builder API rather than string concat; disable DTD/external "
        "entities.",
    ),
    "CWE-943": (
        "Improper Neutralization in Data Query Logic",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Use the datastore driver's parameter binding; validate field names against a "
        "fixed allow-list.",
    ),
    "CWE-116": (
        "Improper Encoding or Escaping of Output",
        "V1.1",
        "Encoding & Sanitization \u203a Architecture",
        "Encode at the last possible moment for the exact sink; centralise in one helper per sink.",
    ),
    "CWE-117": (
        "Improper Output Neutralization for Logs",
        "V16.4",
        "Security Logging \u203a Log Protection",
        "Strip/escape CR-LF and control chars before logging user-controlled strings.",
    ),
    "CWE-1336": (
        "Server-Side Template Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Render user data as *context values* only; never let user input reach the "
        "template *source*.",
    ),
    "CWE-917": (
        "Expression Language Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "Disable EL evaluation on untrusted strings or use a sandboxed evaluator with an "
        "allow-listed function set.",
    ),
    "CWE-20": (
        "Improper Input Validation",
        "V2.2",
        "Validation & Business Logic \u203a Input Validation",
        "Validate type, length, range and format at the trust boundary; reject rather than coerce.",
    ),
    "CWE-1287": (
        "Improper Validation of Specified Type of Input",
        "V2.2",
        "Validation & Business Logic \u203a Input Validation",
        "Assert the exact schema/type (JSON-Schema, protobuf, struct tags) before use.",
    ),
    "CWE-185": (
        "Incorrect Regular Expression",
        "V2.2",
        "Validation & Business Logic \u203a Input Validation",
        "Anchor the regex (`^…$`), escape user-derived fragments, and add a length precheck.",
    ),
    "CWE-1333": (
        "Inefficient Regular Expression (ReDoS)",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Rewrite catastrophic-backtracking patterns (nested `*`/`+`) or switch to "
        "RE2/linear-time engine; cap input length.",
    ),
    "CWE-345": (
        "Insufficient Verification of Data Authenticity",
        "V2.2",
        "Validation & Business Logic \u203a Input Validation",
        "Verify a signature/MAC over the payload before acting on it; reject unsigned callbacks.",
    ),
    "CWE-602": (
        "Client-Side Enforcement of Server-Side Security",
        "V2.3",
        "Validation & Business Logic \u203a Business Logic Security",
        "Repeat every security-relevant check on the server; treat client-side validation "
        "as UX only.",
    ),
    "CWE-807": (
        "Reliance on Untrusted Inputs in a Security Decision",
        "V2.3",
        "Validation & Business Logic \u203a Business Logic Security",
        "Re-derive the decision input from a trusted source (DB, signed token), not from "
        "the request body.",
    ),
    "CWE-354": (
        "Improper Validation of Integrity Check Value",
        "V2.2",
        "Validation & Business Logic \u203a Input Validation",
        "Compare digests with constant-time equality and fail closed on mismatch.",
    ),
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "V4.1",
        "API & Web Service \u203a Generic Web Service Security",
        "Validate the destination against an allow-list *after* DNS resolution; block "
        "link-local/RFC1918/metadata ranges and disallow redirects.",
    ),
    "CWE-441": (
        "Unintended Proxy or Intermediary (Confused Deputy)",
        "V4.1",
        "API & Web Service \u203a Generic Web Service Security",
        "Strip/ignore caller-supplied target URLs and forwarded-auth headers; "
        "re-authenticate downstream with the service's own identity.",
    ),
    "CWE-601": (
        "URL Redirection to Untrusted Site (Open Redirect)",
        "V4.1",
        "API & Web Service \u203a Generic Web Service Security",
        "Only redirect to relative paths or an allow-listed host set; canonicalise before "
        "comparing.",
    ),
    "CWE-444": (
        "HTTP Request/Response Smuggling",
        "V4.2",
        "API & Web Service \u203a HTTP Message Structure Validation",
        "Normalise/validate `Content-Length` vs `Transfer-Encoding` at the edge; reject "
        "ambiguous framing.",
    ),
    "CWE-22": (
        "Path Traversal",
        "V5.3",
        "File Handling \u203a File Storage",
        "`filepath.Clean` + join under a fixed root, then verify the result is still under "
        "that root before open/write.",
    ),
    "CWE-23": (
        "Relative Path Traversal",
        "V5.3",
        "File Handling \u203a File Storage",
        "Reject any path containing `..` after canonicalisation; resolve against a "
        "chroot-like base.",
    ),
    "CWE-73": (
        "External Control of File Name or Path",
        "V5.3",
        "File Handling \u203a File Storage",
        "Map user-supplied names to server-generated IDs; never let the caller choose the "
        "on-disk path.",
    ),
    "CWE-59": (
        "Link Following (Symlink Attack)",
        "V5.3",
        "File Handling \u203a File Storage",
        "Open with `O_NOFOLLOW`/`Lstat`-then-`Open` and verify the resolved inode is "
        "inside the expected directory.",
    ),
    "CWE-434": (
        "Unrestricted Upload of File with Dangerous Type",
        "V5.2",
        "File Handling \u203a File Upload and Content",
        "Validate content-type by *sniffing*, restrict extensions, store outside the web "
        "root under a random name.",
    ),
    "CWE-552": (
        "Files or Directories Accessible to External Parties",
        "V5.4",
        "File Handling \u203a File Download",
        "Serve downloads through a handler that authorises per-object, not by exposing "
        "the storage path.",
    ),
    "CWE-377": (
        "Insecure Temporary File",
        "V5.3",
        "File Handling \u203a File Storage",
        "Create temp files with `os.CreateTemp`/`mkstemp` (0600) instead of predictable "
        "names in `/tmp`.",
    ),
    "CWE-378": (
        "Creation of Temporary File With Insecure Permissions",
        "V5.3",
        "File Handling \u203a File Storage",
        "Pass mode 0600 when creating; on Go set `syscall.Umask` or `os.WriteFile(…, 0600)`.",
    ),
    "CWE-732": (
        "Incorrect Permission Assignment for Critical Resource",
        "V5.3",
        "File Handling \u203a File Storage",
        "Write with 0600/0700 and chown to the service user; on K8s set `fsGroup`/`defaultMode`.",
    ),
    "CWE-276": (
        "Incorrect Default Permissions",
        "V5.3",
        "File Handling \u203a File Storage",
        "Set an explicit restrictive mode at creation time; don't rely on the process umask.",
    ),
    "CWE-61": (
        "UNIX Symbolic Link Following",
        "V5.3",
        "File Handling \u203a File Storage",
        "Use `openat2(RESOLVE_BENEATH)`/`SecureJoin`; never follow symlinks under a "
        "user-writable dir.",
    ),
    "CWE-502": (
        "Deserialization of Untrusted Data",
        "V1.5",
        "Encoding & Sanitization \u203a Safe Deserialization",
        "Use a safe loader (`yaml.safe_load`, `json.Unmarshal` into a fixed struct); "
        "allow-list types; never `pickle`/`ObjectInputStream` untrusted bytes.",
    ),
    "CWE-915": (
        "Improperly Controlled Modification of Dynamically-Determined Object Attributes "
        "(Mass Assignment)",
        "V1.5",
        "Encoding & Sanitization \u203a Safe Deserialization",
        "Bind requests to a DTO with an explicit field allow-list; never `**kwargs`→model.",
    ),
    "CWE-1321": (
        "Prototype Pollution",
        "V1.5",
        "Encoding & Sanitization \u203a Safe Deserialization",
        "Reject `__proto__`/`constructor`/`prototype` keys during merge; use "
        "`Object.create(null)` for maps.",
    ),
    "CWE-470": (
        "Unsafe Reflection",
        "V15.3",
        "Secure Coding & Architecture \u203a Defensive Coding",
        "Map input→class via a fixed table; never `Class.forName`/`getattr` on "
        "caller-supplied names.",
    ),
    "CWE-611": (
        "XML External Entity (XXE)",
        "V1.5",
        "Encoding & Sanitization \u203a Safe Deserialization",
        "Disable DTDs and external entity resolution on the parser before loading untrusted XML.",
    ),
    "CWE-494": (
        "Download of Code Without Integrity Check",
        "V15.2",
        "Secure Coding & Architecture \u203a Security Architecture & Dependencies",
        "Pin the download to a digest and verify the checksum/signature before executing "
        "or importing it.",
    ),
    "CWE-829": (
        "Inclusion of Functionality from Untrusted Control Sphere",
        "V15.2",
        "Secure Coding & Architecture \u203a Security Architecture & Dependencies",
        "Vendor or pin the dependency by digest; review third-party code paths that run "
        "at import time.",
    ),
    "CWE-1104": (
        "Use of Unmaintained Third-Party Components",
        "V15.2",
        "Secure Coding & Architecture \u203a Security Architecture & Dependencies",
        "Replace the dead dependency with a maintained fork or inline the minimal code "
        "you need under your own tests.",
    ),
    "CWE-1395": (
        "Dependency on Vulnerable Third-Party Component",
        "V15.2",
        "Secure Coding & Architecture \u203a Security Architecture & Dependencies",
        "Bump to the fixed version and add a `go.mod`/`requirements` constraint so it "
        "can't regress.",
    ),
    "CWE-1357": (
        "Reliance on Insufficiently Trustworthy Component",
        "V15.2",
        "Secure Coding & Architecture \u203a Security Architecture & Dependencies",
        "Pull only from a mirrored, signed registry; pin by digest, not tag.",
    ),
    "CWE-427": (
        "Uncontrolled Search Path Element",
        "V15.2",
        "Secure Coding & Architecture \u203a Security Architecture & Dependencies",
        "Invoke binaries by absolute path and clear/fix `PATH`/`LD_LIBRARY_PATH` before `exec`.",
    ),
    "CWE-400": (
        "Uncontrolled Resource Consumption",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Bound request size, concurrency and duration; add `context` timeouts and "
        "per-caller rate limits.",
    ),
    "CWE-770": (
        "Allocation of Resources Without Limits or Throttling",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Cap slice/map growth by validated input length; use bounded channels/worker pools.",
    ),
    "CWE-674": (
        "Uncontrolled Recursion",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Add an explicit depth counter/limit or convert to an iterative walk with a bounded stack.",
    ),
    "CWE-405": (
        "Asymmetric Resource Consumption (Amplification)",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Cap fan-out per request and require auth before triggering expensive downstream work.",
    ),
    "CWE-789": (
        "Memory Allocation with Excessive Size Value",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Validate the caller-supplied length against a hard maximum before `make`/`malloc`.",
    ),
    "CWE-409": (
        "Decompression Bomb",
        "V5.2",
        "File Handling \u203a File Upload and Content",
        "Wrap the decompressor in a `LimitedReader` and abort past a fixed expanded-size ceiling.",
    ),
    "CWE-834": (
        "Excessive Iteration",
        "V2.4",
        "Validation & Business Logic \u203a Anti-automation",
        "Bound loop counts by validated input and add a watchdog timeout.",
    ),
    "CWE-190": (
        "Integer Overflow or Wraparound",
        "V15.3",
        "Secure Coding & Architecture \u203a Defensive Coding",
        "Use checked arithmetic / `math.SafeAdd` or validate operand ranges before the "
        "arithmetic drives an allocation or index.",
    ),
    "CWE-787": (
        "Out-of-bounds Write",
        "V1.4",
        "Encoding & Sanitization \u203a Memory, String, and Unmanaged Code",
        "Bounds-check the index/length against the buffer capacity before every write; "
        "prefer safe slice ops.",
    ),
    "CWE-125": (
        "Out-of-bounds Read",
        "V1.4",
        "Encoding & Sanitization \u203a Memory, String, and Unmanaged Code",
        "Validate offset+length ≤ len(buf) before slicing/reading.",
    ),
    "CWE-476": (
        "NULL Pointer Dereference",
        "V15.3",
        "Secure Coding & Architecture \u203a Defensive Coding",
        "Check for nil before dereference on every externally-influenced pointer; return "
        "an error instead of panicking.",
    ),
    "CWE-362": (
        "Race Condition",
        "V15.4",
        "Secure Coding & Architecture \u203a Safe Concurrency",
        "Guard the shared state with a mutex or make the check-and-act a single atomic operation.",
    ),
    "CWE-367": (
        "TOCTOU Race Condition",
        "V15.4",
        "Secure Coding & Architecture \u203a Safe Concurrency",
        "Operate on the file *descriptor* returned by the initial open rather than "
        "re-resolving the path.",
    ),
    "CWE-667": (
        "Improper Locking",
        "V15.4",
        "Secure Coding & Architecture \u203a Safe Concurrency",
        "Acquire locks in a fixed global order; keep critical sections small; use `defer "
        "Unlock()`.",
    ),
    "CWE-416": (
        "Use After Free",
        "V1.4",
        "Encoding & Sanitization \u203a Memory, String, and Unmanaged Code",
        "Null the pointer after free and gate all subsequent access on it; prefer "
        "ownership-tracking abstractions.",
    ),
    "CWE-415": (
        "Double Free",
        "V1.4",
        "Encoding & Sanitization \u203a Memory, String, and Unmanaged Code",
        "Free in exactly one owner; set to NULL after free so a second free is a no-op or "
        "crash-early.",
    ),
    "CWE-252": (
        "Unchecked Return Value",
        "V15.3",
        "Secure Coding & Architecture \u203a Defensive Coding",
        "Handle the error return; on Go, don't `_ =` errors from security-relevant calls.",
    ),
    "CWE-390": (
        "Detection of Error Condition Without Action",
        "V16.5",
        "Security Logging \u203a Error Handling",
        "Propagate or fail closed on the caught error; don't `catch (e) {}` around "
        "security checks.",
    ),
    "CWE-248": (
        "Uncaught Exception",
        "V16.5",
        "Security Logging \u203a Error Handling",
        "Add a top-level recover/except that returns a controlled error instead of "
        "crashing the whole process.",
    ),
    "CWE-703": (
        "Improper Check or Handling of Exceptional Conditions",
        "V16.5",
        "Security Logging \u203a Error Handling",
        "Distinguish error classes and fail closed on the security-relevant ones instead "
        "of swallowing all.",
    ),
    "CWE-754": (
        "Improper Check for Unusual or Exceptional Conditions",
        "V15.3",
        "Secure Coding & Architecture \u203a Defensive Coding",
        "Validate the precondition explicitly and return early with an error rather than "
        "proceeding on partial state.",
    ),
    "CWE-755": (
        "Improper Handling of Exceptional Conditions",
        "V16.5",
        "Security Logging \u203a Error Handling",
        "Catch narrowly, log with context, and choose fail-closed vs retry deliberately "
        "per error class.",
    ),
    "CWE-1188": (
        "Initialization of a Resource with an Insecure Default",
        "V13.2",
        "Configuration \u203a Backend Communication Configuration",
        "Flip the default to the secure value and require an explicit opt-out flag for "
        "the insecure mode.",
    ),
    "CWE-489": (
        "Active Debug Code",
        "V13.4",
        "Configuration \u203a Unintended Information Leakage",
        "Strip debug/pprof/`--insecure` handlers from release builds or gate them behind "
        "localhost + auth.",
    ),
    "CWE-693": (
        "Protection Mechanism Failure",
        "V15.3",
        "Secure Coding & Architecture \u203a Defensive Coding",
        "Remove the bypass flag/code path; make the guard unconditional in production builds.",
    ),
    "CWE-15": (
        "External Control of System or Configuration Setting",
        "V13.2",
        "Configuration \u203a Backend Communication Configuration",
        "Allow-list which settings a caller may set and clamp values to a safe range.",
    ),
    "CWE-942": (
        "Permissive CORS Policy",
        "V3.5",
        "Web Frontend \u203a Browser Origin Separation",
        "Reflect only allow-listed origins; never pair `*` with `Allow-Credentials: true`.",
    ),
    "CWE-16": (
        "Configuration",
        "V13.2",
        "Configuration \u203a Backend Communication Configuration",
        "Set the secure value explicitly in code so it can't be overridden to an unsafe "
        "one at deploy time.",
    ),
    "CWE-923": (
        "Improper Restriction of Communication Channel to Intended Endpoints",
        "V13.2",
        "Configuration \u203a Backend Communication Configuration",
        "Bind admin/debug listeners to localhost or a dedicated interface; require auth "
        "on anything bound to 0.0.0.0.",
    ),
    "CWE-668": (
        "Exposure of Resource to Wrong Sphere",
        "V13.2",
        "Configuration \u203a Backend Communication Configuration",
        "Keep the resource on an internal listener/namespace; front it with an "
        "authenticating proxy if it must be reachable.",
    ),
    "CWE-749": (
        "Exposed Dangerous Method or Function",
        "V4.1",
        "API & Web Service \u203a Generic Web Service Security",
        "Remove the endpoint or require an authenticated + authorised caller; never ship "
        "it enabled by default.",
    ),
    "CWE-472": (
        "External Control of Assumed-Immutable Web Parameter",
        "V2.3",
        "Validation & Business Logic \u203a Business Logic Security",
        "Recompute price/role/owner server-side; ignore hidden/readonly fields from the client.",
    ),
    "CWE-565": (
        "Reliance on Cookies without Validation and Integrity Checking",
        "V7.2",
        "Session Management \u203a Fundamental Session Management Security",
        "HMAC-sign the cookie or store only an opaque id and keep state server-side.",
    ),
    "CWE-778": (
        "Insufficient Logging",
        "V16.3",
        "Security Logging \u203a Security Events",
        "Emit an audit-log record for every authn/authz decision and privileged action, "
        "with actor + object.",
    ),
    "CWE-1021": (
        "Improper Restriction of Rendered UI Layers (Clickjacking)",
        "V3.4",
        "Web Frontend \u203a Browser Security Mechanism Headers",
        "Send `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`).",
    ),
    "CWE-1004": (
        "Sensitive Cookie Without HttpOnly",
        "V3.3",
        "Web Frontend \u203a Cookie Setup",
        "Set `HttpOnly` (and `Secure`, `SameSite`) on every auth/session cookie.",
    ),
    "CWE-614": (
        "Sensitive Cookie Without Secure Attribute",
        "V3.3",
        "Web Frontend \u203a Cookie Setup",
        "Set `Secure` on every cookie that carries auth/session state.",
    ),
    "CWE-644": (
        "Improper Neutralization of HTTP Headers",
        "V4.2",
        "API & Web Service \u203a HTTP Message Structure Validation",
        "Strip CR/LF from any user-derived value before writing it into a response header.",
    ),
    "CWE-113": (
        "HTTP Response Splitting",
        "V4.2",
        "API & Web Service \u203a HTTP Message Structure Validation",
        "Reject header values containing CR/LF; use the framework's header-set API, not "
        "raw writes.",
    ),
    "CWE-917-EL": (
        "(alias) EL Injection",
        "V1.2",
        "Encoding & Sanitization \u203a Injection Prevention",
        "",
    ),
}


class CweReferenceProvider:
    """Read-only reviewed references; unknown CWEs have no invented crosswalk or fix."""

    def __init__(self) -> None:
        self._entries = MappingProxyType(
            {
                identifier: CweReference(
                    identifier=identifier, name=row[0], asvs=row[1], asvs_name=row[2], fix=row[3]
                )
                for identifier, row in _DATA.items()
                if identifier.removeprefix("CWE-").isdigit()
            }
        )

    def get(self, identifier: str) -> CweReference | None:
        return self._entries.get(identifier)
