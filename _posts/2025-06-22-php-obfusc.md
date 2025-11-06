---
title: Deobfuscating a PHP backdoor step by step (safe and practical)
date: 2025-05-22 22:20:00 -0300
categories: [Malware Analysis, Research Web Security]
tags: [PHP, Python, backdoor, deobfuscation, WordPress]
image: "/assets/php/php.png"
image_alt: "PHP + malware: base64 → XOR → eval (not today)"
description: Practical (and safe) guide to identify, decode and remove common PHP backdoors — with neutral examples, Python deobfuscator and incident response checklist.
---

> **Security notice**  
> Everything here is **for defense**. Examples are **neutralized** (don't execute malicious payload) and the analysis script **does not** execute anything — it only decodes and prints for inspection.

## TL;DR
PHP backdoors often hide a payload via **base64 → XOR → (optional) compression** and execute with `eval/assert/preg_replace('/e')`. You can:
1) **Extract** the blob and key  
2) **Decode** it **offline** and safely  
3) **Remove** and **harden** the environment (block execution in `/uploads/`, update, rotate credentials, WAF)

---

## Common vectors
• outdated or nulled plugin/theme  
• upload to `/wp-content/uploads/` with execution enabled  
• leaked FTP/panel credentials  
• insecure includes (`include($_GET['f'])` etc.)

---

## Quick indicators (IOCs)
• `.php` files with image names: `image.php.jpg`, `favicon_abc.ico.php`  
• error suppression: `@`, `ini_set('display_errors',0)`, `error_reporting(0)`  
• indirect execution: `eval`, `assert`, `create_function`, `preg_replace('/e')`  
• IP/User-Agent filters before execution  
• "strange" timestamps in `wp-includes/`, `wp-admin/`, `index.php`

## Stub anatomy (reconstructed and harmless example)

<details>
  <summary><strong>View PHP stub (safe)</strong></summary>
  <pre><code class="language-php">

{% raw %}
<?php
/* payload stored in an "innocent" way */
$blob = 'U1dMQkQAAABfX0RVTU1ZUFJPVEVDSF8...'; // short, fake base64

/* simple key used by attacker */
$key = "k9";

/* common deobfuscation: base64 -> XOR -> (sometimes) zlib -> eval */
$data = base64_decode($blob);

/* XOR byte by byte (recurring pattern) */
$out = '';
for ($i = 0; $i < strlen($data); $i++) {
    $out .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
}

/* In real samples we'd see something like: */
// eval($out);

/* Here, for safety, we only show the size */
echo "Decoded length: " . strlen($out);

{% endraw %}

  </code></pre>
</details>

**Key points**
• the "poison" is hidden in **data**, not in clear code
• the XOR **key** is usually short (1–8 bytes)
• right after decoding comes **execution** (which we must avoid)

---

## Python deobfuscator (safe, no `eval`)

```python

import argparse, base64, binascii, zlib, sys
from pathlib import Path

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def maybe_uncompress(b: bytes) -> bytes:
    try:
        return zlib.decompress(b)
    except Exception:
        try:
            return zlib.decompress(b, wbits=16+zlib.MAX_WBITS)  # gzip
        except Exception:
            return b

def main():
    ap = argparse.ArgumentParser(description="Decode PHP backdoor: base64 -> XOR -> (optional) zlib. No eval.")
    ap.add_argument("-b", "--base64", help="base64 blob", required=False)
    ap.add_argument("-f", "--file", help="file with base64 blob", required=False)
    ap.add_argument("-k", "--key", help="XOR key (text)", default="")
    ap.add_argument("--hexdump", action="store_true", help="show short hexdump")
    args = ap.parse_args()

    if not args.base64 and not args.file:
        ap.error("provide --base64 or --file")

    b64 = args.base64 or Path(args.file).read_text().strip()
    try:
        raw = base64.b64decode(b64, validate=True)
    except binascii.Error as e:
        print(f"[!] invalid base64: {e}")
        sys.exit(1)

    xored = xor_bytes(raw, args.key.encode())
    dec  = maybe_uncompress(xored)

    print(f"[+] base64 bytes: {len(raw)}")
    print(f"[+] after XOR:    {len(xored)}")
    print(f"[+] final:        {len(dec)} bytes")
    print("\n----- BEGIN OUTPUT (text preview) -----")
    print(dec.decode("utf-8", errors="replace"))
    print("----- END OUTPUT -----")

    if args.hexdump:
        print("\n[hexdump 64B]")
        print(" ".join(f"{b:02x}" for b in dec[:64]))

if __name__ == "__main__":
    main()
```

**Quick usage**

```bash
python3 deob.php.py -f blob.txt -k k9
python3 deob.php.py -b 'AAA...' -k secret --hexdump
```

---

## Practical analysis workflow

1. **Backup/Snapshot** the site before anything.
2. **Isolate** the suspicious file; don't run it on the server.
3. **Extract** the `blob` and `key` (regex helps):

   * `base64_decode\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)`
   * `\^|xor` to find the key
4. **Decode offline** with the script.
5. **Inspect output** for behavior: `system/exec`, exfiltration, webshell.
6. **List IOCs**: paths, parameters, C2 domains, hashes.
7. **Remediation**: clean, rotate passwords/keys, update plugins/themes/core, apply WAF.

---

## Before and after

{% raw %}

```php
<?php $a="U1dMQkQ...";$k="k9";$d=base64_decode($a);
for($i=0,$o='';$i<strlen($d);$i++){$o.=chr(ord($d[$i])^ord($k[$i%strlen($k)]));}
@assert($o); // in real samples
```

```php
/* reconstructed and harmless example */
$cmd = $_POST['cmd'] ?? null;
if ($cmd === 'ping') { echo "pong"; }
```

{% endraw %}


---

## Source code detection (grep/regex)

Useful searches:

```bash
# dangerous functions
rg -n "eval\s*\(|assert\s*\(|create_function\s*\(|preg_replace\s*\(.*\/e" -S

# base64 + decode
rg -n "base64_decode\s*\("

# patterns with gzinflate/rot13
rg -n "(gzinflate|str_rot13)\s*\("

# stealthy writing
rg -n "file_put_contents\s*\(|fopen\s*\("

# dynamic include
rg -n "include|require" -g '!vendor/**'
```

---

## Hardening the environment (Nginx/Apache)

**Block PHP in `/uploads/`**

Nginx:

```nginx
location ~* ^/wp-content/uploads/.*\.php$ { return 403; }
```

Apache (.htaccess):

```apache
<Directory "/var/www/html/wp-content/uploads/">
  php_admin_flag engine off
  <FilesMatch "\.php$">
    Require all denied
  </FilesMatch>
</Directory>
```

**Other measures**
• disable `allow_url_include` and, if possible, restrict with `open_basedir`
• keep `display_errors=Off` in production and centralized logs
• use WAF (rules for known webshells/obfuscators)

---

## Hunting and telemetry (ideas)

• **modified file + HTTP request** with suspicious parameter → **PHP process** running `system/exec`
• **spikes in `base64_decode`/`gzinflate`** in trace sampling
• **behavioral signature**: decodes data + executes string
• **IOC table** (paths/domains) propagated to SIEM

---

## Reducing false positives

• legitimate deobfuscators exist, so require **two signals**: decoding + execution
• ignore paths of **known libraries** (vendor, libs) when appropriate
• observe **short windows**: stubs usually "light up" right after upload

---

## Closing

At the end of the day, much of the "magic" in these backdoors is just **cheap obfuscation** to avoid drawing attention in a diff. Decoding safely, understanding the sequence and cutting off the vectors is usually enough to dismantle the operation.