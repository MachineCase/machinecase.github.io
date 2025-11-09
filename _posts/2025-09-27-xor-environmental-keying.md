---
title: "Environmental keying: 16-byte key derived from uptime"
date: 2025-09-27 20:37:00 -0300
categories: [Malware Analysis, Security Research]
tags: [XOR, Environmental Keying, Detection, YARA]
image: "/assets/xor/xor.jpg"
---

> **Security notice**
> This article is 100% defensive and academic. Code examples are **neutralized** for analysis and detection — they do not show or execute payloads. The goal is to explain the technique, show weaknesses and offer actionable heuristics to hunt and prevent this family of attacks.

## Quick summary

Some threat actors use “environmental keying”: they derive a runtime key from system properties (time, uptime, PID, MAC address, etc.). Here we focus on a specific pattern: **a 16-byte (128-bit) key derived from system uptime**, combined with pieces (split) embedded in the binary (head + tail). The mechanism gives the attacker resistance against simple static extraction, but it produces detectable signals in static and dynamic analysis.

Below I describe:

* implementation variants (3 practical schemes),
* neutralized reconstruction code (read/derive only),
* weaknesses and defensive attack vectors (window brute-force, overlay analysis),
* heuristic rules (YARA/PCRE) and instrumentation ideas to hunt.

---

## Threat model and motivation

Attacker motivation:

* Do not store the key in clear in the binary (increases stealth).
* Make the key depend on the environment (avoid detection by simple static comparisons).
* Allow the operator who controls the binary (or knows the scheme) to reconstruct the key without the full key stored.

Problems for the defender:

* The key is not in clear text, it is dispersed and depends on a predictable quantity `uptime`.
* The attacker can “split” metadata to reduce static surface area.

Defender benefit:

* `uptime` is predictable; with appropriate heuristics it is possible to recover the key (or brute-force within a plausible window).
* Operationally the pattern generates consistent telemetry (self-reads, time syscalls and hashing, XOR loops) — very useful for behavioral detection.

---

## How the attacker commonly implements it (simplified pattern)

1. At runtime the program obtains `uptime` (e.g. `clock_gettime(CLOCK_MONOTONIC)` or `mach_absolute_time()` on macOS).
2. It computes `K = SHA256(some_material || uptime_bytes || other_material)[:16]`.

   * `some_material` / `other_material` may include embedded seeds, MAC, PID or pieces stored in the binary (split).
3. Uses `K` to encrypt/decrypt via XOR or a lightweight stream cipher.
4. To allow the operator to know `K` later, they place `seed` in two locations in the binary (for example: 8 bytes at the start and 8 bytes at the end), or use another split scheme that can be recomposed at runtime.

> Note: using `uptime` as the only source of entropy makes the scheme vulnerable to window brute-force; mixing additional sources increases entropy but also increases the number of reads/syscalls that can be detected.

---

## Three practical schemes (conceptual)

### Scheme A — `seed_hi` + `seed_lo` XOR with uptime → hash

* Binary stores `seed_hi` (8 bytes) at the beginning and `seed_lo` (8 bytes) at the end.
* Runtime:

  * `u = uptime_ns` (8 bytes)
  * `buf = (seed_hi XOR u) || (seed_lo XOR u)`  → `hash = SHA256(buf)` → `K = hash[:16]`
* Tradeoff: simple, but if `u` is predictable it suffices to test time windows.

### Scheme B — store half the key and recompute the other half

* Binary stores `K_partA` (8 bytes) at the start, computes `K_partB = SHA256(u || nonce)[:8]` at runtime.
* `K = K_partA || K_partB`
* Tradeoff: reduces workload for an attacker who already has `K_partA`; defender can brute-force `u` to recover `K_partB`.

### Scheme C — `K = SHA256(seed || uptime || nonce)[:16]`

* Binary stores `seed` and `nonce` in distinct places; combines with uptime.
* More robust if `seed` and `nonce` are secret; still vulnerable if `uptime` is the only unknown entropy.

All schemes can be used with byte-by-byte XOR or as a 128-bit key for block XOR (neutralized: **we do not** provide payload encryption implementations here; only reconstruction / hunting techniques).

---

## Neutralized code: reconstructing the key from head+tail + uptime (C)

> Warning: this code **only** shows how to reconstruct the key (useful for analysts). It does not perform or show payload encryption. On macOS reading the current binary requires different methods (see notes below).

```c
// This code implements Scheme A. For Schemes B and C,
// the logic that builds the 'buf' buffer and the hash
// calculation should be adjusted according to the article.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    const char *path = "sample_binary.bin";
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    unsigned char head[8], tail[8];
    if (pread(fd, head, 8, 0) != 8) { perror("pread head"); close(fd); return 1; }

    struct stat st;
    if (fstat(fd, &st) != 0) { perror("stat"); close(fd); return 1; }
    off_t sz = st.st_size;
    if (sz < 16) { fprintf(stderr, "file too small\n"); close(fd); return 1; }

    if (pread(fd, tail, 8, sz - 8) != 8) { perror("pread tail"); close(fd); return 1; }
    close(fd);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t uptime_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    unsigned char buf[16];
    for (int i = 0; i < 8; ++i) {
        buf[i] = head[i] ^ ((uptime_ns >> (i*8)) & 0xFF);
        buf[8+i] = tail[i] ^ ((uptime_ns >> ( (i%8)*8)) & 0xFF);
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(buf, sizeof(buf), digest);

    unsigned char key[16];
    memcpy(key, digest, 16);

    printf("derived key: ");
    for (int i=0;i<16;i++) printf("%02x", key[i]);
    printf("\n");
    return 0;
}
```

**macOS specific notes**

* `/proc/self/exe` does not exist. To read the current executable use `_NSGetExecutablePath`, `proc_pidpath` (libproc) or paths passed to the analyst.
* `mach_absolute_time()` is often used instead of `clock_gettime` on macOS; adapt uptime reading according to platform.

---

## How an analyst can recover the key when `uptime` was not stored

* **Window brute-force**: if the author did not store the exact instant, the analyst can test a plausible window of uptimes (for example ±N minutes around the likely execution time). Each attempt produces a candidate key — validate it against some confirmation (embedded checksum, known header or try to decode a small portion that should be plausible).
* **Constraints**: higher resolution (nanos vs seconds) increases search space; if the author used nanos the search can be impractical without extra hints. However, many authors use second or minute granularity to make the technique practical for them; this is a weakness.

> Operational tip: combine brute-force with plausibility heuristics (decoded ASCII strings, magic bytes PNG/ELF/Mach-O) to reduce defender cost.

---

## Detectable signals — practical heuristics

### Static

* **Overlay / appended data**: executables with extra data at the end (tail) or with high-entropy content right at the beginning (head). Entropy-by-window scripts commonly detect this.
* **Metadata pieces at start/end**: constant byte sequences of 8–32 bytes in unusual regions.
* **Strings related to hashing**: presence of `SHA256`, `SHA1`, `OpenSSL` (statically linked) in combination with file read operations.

### Dynamic / behavioral

* Typical sequence: `open(self)` → `pread(head)` → `pread(tail)` → `clock_gettime` / `mach_absolute_time` → `SHA256` → XOR/decoding loop → action (file write, network).
  Monitor and correlate by process and within short time windows.
* Self-binary reads with small offsets (0 and EOF-8) followed by hashing library calls.
* Network connections soon after decoding (e.g., upload of payload or beacon).

---

## Countermeasures and mitigation

For operators and response teams:

* Block arbitrary uploads/execution on hosts (WAF/mod_security policies for pages serving HTA/JS malicious content).
* Check artifacts for overlays (size vs expected image) during forensic intake.
* Use EDR/telemetry to identify pattern: `read-self` + `hash` + `xor` + `network`.
* Triage: prioritize samples with appended data and time + hashing calls.

For defensive architectures:

* Prevent unprivileged processes from reading sensitive areas unnecessarily.
* Enable detection of unusual self-binary reads on critical hosts.

---

## Variations and hardenings the attacker may apply

* **Add PID/MAC/hostname to the hash input** → increases entropy, but adds detectable activities (interface reads, syscalls).
* **Rounding/quantization of uptime** (e.g. uptime in minutes) → reduces operator precision but makes brute-force easier.
* **Obfuscation of the reads** (use trampolines, wrappers, syscall indirections) → slows analysts, but telemetry correlation remains possible.

In short: hardenings make the technique more costly for both attacker and analyst; from a defensive perspective, telemetry correlation is the most robust path.

---

## Practical YARA and PCRE examples

> Use these as a starting point; tune for your environment and evaluate false positives.

**PCRE:**

```
/(pread|fread|read).{0,200}(CLOCK_MONOTONIC|mach_absolute_time|clock_gettime).{0,400}(SHA256|CC_SHA256|SHA1)/is
```

**YARA concept:**

```
rule possible_uptime_keying_generic {
  meta:
    author = "you"
    desc = "heuristic: head/tail seeds + hashing usage"
  strings:
    $s1 = "SHA256" ascii nocase
    $s2 = "mach_absolute_time" ascii
    $s3 = "clock_gettime" ascii
    $bytecodeOSX = { 31 ?? e8 ?? ?? ??} // example of generic bytecode based on behavior
    $bytecodeOSLinux = { 27 48 ?? e8 ?? ?? ??} // example of generic bytecode based on behavior
  condition:
    filesize > 64KB and 
    (
      $s1 and 
      ($s3 or $s3) and 
      ($bytecodeOSX or $bytecodeOSLinux)
    )
}
```

---

## Quick checklist for analysts

1. Check if a binary has appended data (tail) / high-entropy head.
2. Prove: extract 8–16 bytes from head and tail and try combinations with coarse `uptime` (seconds/minutes).
3. If you recover a candidate key, attempt to decode an initial block (first KB) and look for plausible ASCII / magic bytes.
4. Correlate with telemetry: self-binary read, time syscall, hashing, write/transfer activity.
5. If confirmed, generate IOCs (hashes, strings, offsets) and create tuned YARA/PCRE rules.

---

## Conclusion

Deriving keys from uptime with splits in the binary is an elegant obfuscation trick: it removes the explicit key from the binary and requires runtime recomposition. In practice this trick tends to fail against defenses equipped with:

* instrumentation able to correlate reads and hashing,
* static scanning for overlays and high entropy,
* and, when necessary, defender brute-force within plausible windows.

---