# Whisper - Analysis README

**Short summary:**  
This repository contains analysis notes, IOCs, and detection guidance for a sample we refer to as **Whisper** - a minimal **HTTP beacon-only C2 client**. The sample registers (optionally) via `/add.php` and periodically issues keep‑alive requests to `/ping.php`. The analyzed sample itself does not implement command execution, but the C2 operator has been observed delivering a PE (e.g. `calc.exe`) to selected targets on manual approval.

### PASSWORD FOR ARCHIVE IS: Mr128Bit

---

## Table of contents
- [What is Whisper?](#what-is-whisper)
- [Observed behavior (at a glance)](#observed-behavior-at-a-glance)
- [Technical details & functionality](#technical-details--functionality)
- [Network IOCs & request patterns](#network-iocs--request-patterns)
- [Detection rules / signatures (examples)](#detection-rules--signatures-examples)
- [Hunting queries (SIEM / Splunk examples)](#hunting-queries-siem--splunk-examples)
- [Recommended mitigation & response](#recommended-mitigation--response)
- [Disclaimer](#disclaimer)

---

## What is Whisper?

**Whisper** (sample name) is a small HTTP C2 client whose primary behavior in the analyzed sample is **beaconing**. The client:

- Optionally registers with a C2 server (via `add.php`).
- Periodically performs HTTP GET requests to `ping.php` with query parameters that include an agent ID and version fields.
- Reads a small response (~0x800 bytes) but **does not** parse or act upon it in the observed code path.

In observed server-side interactions, the operator could manually deliver a PE to a target after verification (e.g., operator authentication, target selection, or checking that the target IP was not previously acted upon). That manual, conditional payload delivery makes the infrastructure more dangerous despite the minimal client.

---

## Observed behavior (at a glance)

1. On startup the binary may perform a registration request to `/add.php`.
2. The binary enters a loop building a request like:
   ```
   GET /ping.php?v=<ver>&a=<agent>&e=<num>&c=<num> HTTP/1.0
   Host: <C2-ip>:80
   ```
3. The client sends the GET, receives up to ~0x800 bytes of response, null-terminates the buffer, and closes the socket.
4. The client does not evaluate the response to decide next actions (no command parsing or downloader logic is present in the sample).
5. The C2 operator can, outside the sample, deliver binaries to selected hosts.

---

## Technical details & functionality

- Network: TCP sockets to port 80 (plain HTTP, no TLS).
- Request: HTTP/1.0 GET with `Host:` header only (no User-Agent).
- Query parameters typically include:
  - `v` - version or numeric token
  - `a` - agent/client identifier (string)
  - `e`, `c` - numeric fields (purpose unknown)
- Anti-analysis: timing check using `gettimeofday()` and `sleep(10)` to detect shortened sleeps (anti-sandbox).
- Thread-safety: internal syscall wrappers use TLS-based locking (futex-like).
- Memory: uses custom `heap_alloc` / `heap_free` helpers.
- No automatic persistence or execute-after-download in the analyzed code path.

---

## Network IOCs & request patterns

> Replace C2 IP/host and any strings below with values from your sample before use.

- C2 IP / hostname example: `31.170.22.205`
- Endpoints:
  - `/add.php`
  - `/ping.php`
- Example request pattern:
  ```
  GET /ping.php?v=%u&a=%s&e=%u&c=%u HTTP/1.0
  Host: 31.170.22.205:80
  ```

If you can extract the agent string (e.g., a static string embedded in the binary), add it to your IOCs.

---

## Detection rules / signatures (examples)

**Suricata (HTTP URI)**:
```text
alert http any any -> any any (msg:"WHISPER C2 registration add.php"; http.uri; content:"/add.php"; nocase; sid:1000001; rev:1;)
alert http any any -> any any (msg:"WHISPER C2 beacon ping.php"; http.uri; content:"/ping.php"; nocase; sid:1000002; rev:1;)
```

**Suricata (suspected EXE download detection)**:
```text
alert http any any -> any any (msg:"WHISPER C2 suspected EXE download"; http.response; content:"MZ"; within:8; pcre:"/Content-Disposition:.*\\.exe/i"; sid:1000003; rev:1;)
```

**YARA (simple strings-based)**:
```yara
rule WHISPER_beacon_strings {
  meta:
    description = "Whisper beacon-only client (strings)"
    author = "Robin Dost (Mr128Bit)"
    date = "2025-10-15"
  strings:
    $s1 = "add.php" nocase
    $s2 = "ping.php" nocase
    $s3 = "GET %s HTTP/1.0" ascii
  condition:
    any of them
}
```

---

## Hunting queries (SIEM / Splunk examples)

**Find frequent beaconers (Splunk example)**:
```spl
index=network sourcetype=proxy OR sourcetype=web
| where like(uri, "%/ping.php%") OR like(uri, "%/add.php%")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src_ip, dest_host, uri
| where count > 50
| sort - count
```

**Correlate beacon then EXE download**:
```spl
index=network
| eval is_beacon = if(like(uri, "%/ping.php%") OR like(uri, "%/add.php%"),1,0)
| eval is_exe = if(response_body_may_contain_mz==1 OR like(response_headers, "%Content-Disposition%exe%"),1,0)
| stats earliest(_time) as first_beacon latest(_time) as last_beacon, max(is_exe) as exe_download by src_ip, dest_host
| where sum(is_beacon)>5 AND exe_download=1
```
*(Adjust field names to your log schema; `response_body_may_contain_mz` is a placeholder for content inspection results.)*

---

## Recommended mitigation & response

1. **Block & isolate**: Block C2 domain/IP and related paths at perimeter/proxy; isolate hosts contacting the C2.  
2. **Collect evidence**: PCAPs, webserver logs, binary samples, process/memory snapshots.  
3. **Hunt**: Search for hosts with repeated beacon behavior and correlate for downloads.  
4. **Eradicate & recover**: Remove binaries, clean persistence if found, reimage if necessary. Rotate credentials if operator-level access was observed.  
5. **Monitor**: Continue monitoring for re-arming activity (operator could later deliver payloads).

---

## Disclaimer

This document contains analysis notes and detection examples intended for defensive use. Do **not** run unknown binaries on production systems. The author provides no warranty and is not liable for misuse of the information.

---

## Contact / Contribution

If you have further artifacts (sample hash, C2 domain, server-side logs), open an issue or submit a pull request with sanitized IOCs. Contributions and corrections are welcome.

