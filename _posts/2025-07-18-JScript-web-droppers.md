---
title: JScript "////" web droppers, extracting payloads via regex
date: 2025-07-18 23:59:00 -0300
categories: [Malware Analysis, Research Web Security]
tags: [JScript, HTA, Regex, Dropper]
description: How to identify and extract, safely and without execution, payloads marked with “////” in JScript/HTA served via the web with regex, neutralized examples, a Python extractor, and a playbook for hosting environments.
image: "/assets/jscript/2h8x90.jpg"
---

> **Security notice**  
> 100% defensive post. Examples are **neutralized** (they do **not** execute payloads). The extractor **does not execute** code — it only locates and decodes `////` marked blobs for offline analysis.

## Context (why this matters for hosting)

In real incidents, web servers (including **shared hosting** environments) end up serving malicious HTML/HTA that abuses **JScript** (Internet Explorer/HTA) with **ActiveX**. A recurring pattern in *droppers* is to “hide” the payload in base64/hex blocks visually marked with `////`, then reassemble and decode on the client with `Replace/Join` before doing *write-to-disk* and *exec* via `ADODB.Stream` and `WScript.Shell` (in HTA, for example).

From a **blue team/forensics** point of view at a hosting provider, you want to:
- quickly locate these marked blobs,
- extract the content **without execution**, 
- generate IOCs (hashes/domains/filenames) and block further dissemination from the compromised host.

---

## “////” dropper pattern in JScript (web/HTA)

Three common signals (with variations):

1) **Visual markers**: `////` in long strings (base64/hex)  
2) **Split/Join/Replace** for reassembly: e.g., `Split(payload,"////")` or `Replace(payload,"////","")`  
3) **ActiveX** (in HTA/IE): `new ActiveXObject("ADODB.Stream")`, `WScript.Shell`, `Scripting.FileSystemObject`

Below is a **neutralized example** that mimics the pattern (without executing anything dangerous):


```html
<!-- sample-big-slashes.hta (neutralized) -->
<html>
<head>
<meta http-equiv="x-ua-compatible" content="IE=9" />
<title>Neutralized JScript //// demo</title>
<script language="JScript">

// neutralized: no atob, no ActiveX, no ADODB.Stream, no exec.
// only cleanup of '////' markers and byte counting.

function drpp() {

  // Wall of “text” (mix of words and base64) with //// scattered.
  // The idea is to look visually noisy, like real droppers.

  var p =
"// preconize loeti right eidetik nonchafing jurical ////QUFBQkNEREU\n" +
"// superagiety counterdrain coscuwod doutous ternelate ////RkdISUpLTE0=\n" +
"// autonomous unperishably upsey millennial forfep ////TkpPUFFSU1RV\n" +
"// jersial hyalopiarte dorhawk retmept spearhead ////VldYWVo9PT0=\n" +
"// quinodiation endomesoderm semigelative ////Ly8vLy8vLy8vLy8v\n" +
"// toxichemia thril unsupermanaded decomponible ////QUJDREVGR0hJ\n" +
"// kagn stemy hypothaecary halidon altrose ////SktMTU5PUFFSU1RV\n" +
"// exihibitional counterblow naifly cushy ////VldYWVo7Ozs7Ozs7\n" +
"// osteoglossid syncretistic alviducous tean ////c2FmZS1kZW1vLXN0\n" +
"// snuffing paster instrumentalize coped ////cmluZw==////Ly8v\n" +
"// deading particularist quarten bluland ////U291bmRzLWxpa2UtY29kZQ==\n" +
"// incremental betoil unscrutable eo ////Ly8gYmVuaWduX2Jsb2I6Ci8v\n" +
"// gendarme klendusity patelline ////QUFB////QkJC////Q0ND////\n" +
"// gynephobia priscian butyne strind ////REVF////RkZG////R0dH\n" +
"// postpubic damsel jiffy garlick ////Ly8vLy8vLy8vLy8vLy8vLy8v\n" +
"// cranemortal edanitis naporited ////bG9yZW0tc2VicmEtdmlzdWFs\n" +
"// planula elops palt coquire ////YW5jaG9yLWZpbGxlci0vLy8vLy8=\n" +
"// varioform underread overconsciousness ////YXJjaGl2ZS1waWVjZQ==\n" +
"// gyrocaren hospcatcher plumbaginaceae ////Ly8gLy8gLy8gLy8gLy8g\n" +
"// dorsoscupiae rhumatismal intertwining ////QVBQRU5E////TUVUQURB\n" +
"// dimber chariorscurist clench greenback ////VEFHVy8vLy8vLy8v\n" +
"// dorsoscapular zoe sticksnaph ////UEhQLUpTY3JpcHQtbGlrZQ==\n" +
"// --- visual break --- ////Ly8tLS0tLS0tLS0tLS0tLS0tLS0t\n" +
"// assorted words to drown patterns ////Ly8gZGlzdHJpYnV0ZWQtbWFya2Vy\n" +
"// more filler more filler more ////Ly8gLy8gLy8gLy8gLy8gLy8g\n" +
"// even more filler with //// placed ////Ly8gLy8gLy8gLy8gLy8g\n" +
"// around long stretches that look like base64 ////QUJDREVGR0hJSktMTU5PUFFSU1RV\n" +
"// but everything stays neutralized ////VldYWVo=\n" +
"// ---------------------------------------- ////Ly8vL2VuZA==\n" +
"////QUFBQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaQUFBQ0RFRkdISQ==\n" +
"////SktMTU5PUFFSU1RVVldYWVo7Ozs7Ozs7Ly8vLy8vLy8vLy8vLy8=\n" +
"////c2FmZS1kZW1vLW9ubHktY291bnQtbGVuZ3RoLWhlcmU=\n" +
"////bW9yZS10ZXh0LW1vcmUtcmFuZG9tLXdvcmRzLW1vcmU=\n" +
"////Ly8tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0=\n" +
"// final chunk just to look big ////U3RpbGwtbm9uLWV4ZWM=\n";

  // Cleanup: remove '////' and whitespace/newlines (no decoding).
  var cleaned = p.replace(/\/\/\/\/+/g, "").replace(/\s+/g, "");

  // Neutral report: show size and a small ASCII preview (printable).
  var printable = "";
  for (var i = 0; i < cleaned.length && printable.length < 96; i++) {
    var ch = cleaned.charCodeAt(i);
    if (ch >= 32 && ch < 127) printable += cleaned.charAt(i);
    else printable += ".";
  }

  var out = []
  out.push("lines: " + p.split(/\n/).length);
  out.push("size after cleanup: " + cleaned.length + " bytes");
  out.push("ascii preview (96): " + printable);

  // Display in the page's <pre id="out">
  document.getElementById("out").innerText = out.join("\n");

  // Note: in real samples, you'd see:
  //   var b = atob(cleaned);                 // (do not do here)
  //   var s = new ActiveXObject('ADODB.Stream');  // (do not use)
  //   s.Type = 1; s.Open(); s.Write(b); s.SaveToFile('...'); // (no)
  //   new ActiveXObject('WScript.Shell').Run('...');         // (no)
}
</script>
</head>
<body onload="drpp()" style="background:#0b0f14;color:#cfe8ff;font-family:Consolas,Menlo,monospace;">
  <h3 style="margin:16px 24px;">Neutralized JScript //// visual</h3>
  <pre id="out" style="margin:0 24px 24px; padding:16px; border:1px solid #123; background:#0f141c;"></pre>
</body>
</html>

````

> Note: HTML pages with `language="JScript"` and **HTA (`.hta`)** are the most common variants on the legacy “web side” (IE/Windows). The Linux server may be **only serving** the malicious artifact — which is why detecting it in the host’s static content is useful.

---

## Safe extraction via regex (no execution)

The idea: **scan the file** (`.html`, `.hta`, `.js`) for blocks with `////`, **clean** the markers, try to **decode** as base64/hex, **save the bytes** to a file **without executing** anything.

```python
#!/usr/bin/env python3
import re, base64, binascii, sys, pathlib, hashlib

# Usage: python3 safe_extract_slashes.py sample.hta

def find_slash_chunks(text: str):
    """
    Capture sequences with //// that are likely fragmented base64/hex.
    - Strategy 1: '////' followed by a long run of [A-Za-z0-9+/=]
    - Strategy 2: multiple occurrences concatenated
    """
    pattern = re.compile(r"(?:\/\/\/\/[A-Za-z0-9+/=\s]{20,}){2,}", re.S)
    return [m.group(0) for m in pattern.finditer(text)]

def cleanup_markers(blob: str) -> str:
    cleaned = re.sub(r'\/\/\/\/+', '', blob)
    cleaned = re.sub(r'\s+', '', cleaned)
    return cleaned

def try_decode(s: str) -> bytes | None:
    t = s
    rem = len(t) % 4
    if rem:
        t += "=" * (4 - rem)
    try:
        return base64.b64decode(t, validate=True)
    except Exception:
        pass
    hs = re.sub(r'\s+', '', s)
    try:
        return bytes.fromhex(hs)
    except Exception:
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 safe_extract_slashes.py <file>")
        sys.exit(1)

    p = pathlib.Path(sys.argv[1])
    text = p.read_text(errors="ignore")
    chunks = find_slash_chunks(text)

    if not chunks:
        print("[!] no ////-style blobs found")
        sys.exit(0)

    base = p.stem
    outdir = p.parent / f"{base}_extracted"
    outdir.mkdir(exist_ok=True)

    n_hits = 0
    for i, raw in enumerate(chunks, 1):
        cleaned = cleanup_markers(raw)
        data = try_decode(cleaned)
        if data is None:
            (outdir / f"blob_{i:02d}.txt").write_text(cleaned)
            print(f"[-] undecodable blob_{i:02d}.txt (saved for manual review)")
            continue

        sha256 = hashlib.sha256(data).hexdigest()
        out_path = outdir / f"payload_{i:02d}_{sha256[:12]}.bin"
        out_path.write_bytes(data)
        print(f"[+] extracted {len(data)} bytes -> {out_path} (sha256:{sha256})")
        n_hits += 1

    print(f"[=] done. extracted: {n_hits}")

if __name__ == "__main__":
    main()
```

**How to use**

```bash
python3 safe_extract_slashes.py sample.hta
```

---

## Useful regexes (for quick triage)

**Find blocks with `////` (continuous base64):**

```
(?:\/\/\/\/[A-Za-z0-9+/=\s]{20,}){2,}
```

**Find reconstructions (Join/Replace) using `////`:**

```
(?:Split|Join|Replace)\s*\([\s\S]*?\/\/\/\/[\s\S]*?\)
```

**String concatenation with +:**

```
["']\/\/\/\/[A-Za-z0-9+/=\s]{10,}["'](?:\s*\+\s*["'][A-Za-z0-9+/=\s]{10,}["']){1,}
```

**ActiveX heuristic (HTA/IE JScript):**

```
ActiveXObject\s*\(\s*["'](?:ADODB\.Stream|WScript\.Shell|Scripting\.FileSystemObject)["']\s*\)
```

**“Marker + ActiveX” combo (strong):**

```
\/\/\/\/[\s\S]{0,500}ActiveXObject
```
---

## Hunting in hosting environments

Even when the final target is Windows/IE, the **server** hosting the artifact leaves traces. Ideas:

* **File hunting** in the customer’s webroot:

  * Suspicious names: `*.hta`, `*.html` outside CMS, `index_old.html`, `update_login.htm`
  * Strings: `////`, `ActiveXObject`, `JScript.Encode`, `atob(`
  * **mtime** differences outside the deploy window

* **Access logs** (Nginx/Apache):

  * Spikes in **`.hta`/`.js` downloads**
  * Strange referrers pointing to `login/` or `invoice/`

* **WAF (mod_security)**

  * Simple rule (conceptual): block responses that contain **repeated `////` sequences** **AND** `ActiveXObject` (low FP chance on modern sites)

---

## Practical hardening (hosting)

**Block `.hta` on the web server** (almost nobody legitimately serves HTA):

Nginx:

```nginx
location ~* \.hta$ {
  default_type text/plain;
  return 403;
}
```

Apache:

```apache
<FilesMatch "\.hta$">
  Require all denied
</FilesMatch>
```

**Sanitize shared webroots**

* Disable upload/execution of types not used by the customer
* Periodic scans for `////` signatures
* Notify the customer when a suspicious artifact is published

---

## “Before and after” (neutralized)

Before: snippet with //// (benign for demonstration)

```js
var payload =
  "////U29tZUJhc2U2NA==" +
  "////TW9yZU5vaXNl" +
  "////";
var cleaned = payload.replace(/\/\/\/\/+/g, "");
```

After: extracted bytes (pseudo-output)

```text
[+] extracted 21 bytes -> sample_extracted/payload_01_1a2b3c4d5e6f.bin (sha256: 9f2...c1a)
```

---

## Limitations and false positives

* The `////` marker is **not exclusive** to malware; some devs use it as a visual separator. So, combine it with signals like **ActiveX** or `atob` + `Replace/Join`.
* In modern variants, attackers may change the order: `hex → inflate → base64`, or apply **XOR** before base64. The extractor above saves **undecodable** blobs for manual review.

---

## Closing

The “`////` + reassembly + decoding” pattern is practical to hunt for, including in Linux hosting environments that only **serve** the malicious page. The operational win comes from **extracting without execution**: you get IOCs quickly and avoid detonating on a sandbox/client.
