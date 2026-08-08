---
title: "When SEA Met LRE: What Dart's Hidden Code Taught Me About macOS Defense Evasion"
date: 2026-08-08 05:27:00 -0300
categories: [Malware Analysis, Security Research]
tags: [Dart, AOT, Reverse Engineering, blutter, macOS, Mach-O, LC_NOTE, Reflective Loading, MITRE]
image: "https://mateusalvadori.com.br/wp-content/uploads/2022/07/heg.jpg"
---

In May, I published two articles that seemed unrelated: the first was about [Node.js Single Executable Applications](/posts/sea-node-defenseEvasion/), how attackers embed JavaScript into self-contained binaries that evade static scanners, and the second was about [Reverse engineering Dart AOT binaries](/posts/dart-reverse-macos/) on macOS, where I stumbled into a discovery: **Dart's compiler hides compiled application code inside a Mach-O load command called `LC_NOTE`**. Two months later I connected the dots and arrived at this synthesis.

---

## Thesis: SEA and Its Unfixable Fingerprints

A Node.js SEA binary carries the entire Node.js runtime, V8, libuv, the event loop, compressed into a single executable, and attackers like it because it delivers JavaScript without requiring Node.js on the target, but every SEA binary carries immutable artifacts that no amount of obfuscation can remove:

| Artifact | Location | Detectable? |
|----------|----------|-------------|
| `NODE_SEA_BLOB` section | Mach-O / PE / ELF | YES `strings` |
| `__NODE_SEA` segment | Mach-O only | YES `otool -l` |
| Magic `20 DA 43 01` | First 4 bytes of blob | YES YARA |
| Binary size 50-100MB | File size | YES `ls -lh` |

I built a Binary Ninja SEA Analyzer and documented the immutable surface, but the more I studied SEA the more one fact bothered me: the `NODE_SEA_BLOB` section is what makes the technique work and it is also what makes it detectable, because the wrapper that protects the payload is the same wrapper that betrays it, and this internal contradiction is the engine that drives everything that follows.

---

## Antithesis: LC_NOTE, The Hidden Container

While building `blutter-macos`, my fork of the Dart reverse engineering tool, I noticed something in the Mach-O structure:

```
$ otool -l hello | grep -A5 LC_NOTE
      cmd LC_NOTE
  cmdsize 40
data_owner __dart_app_snap
    offset 4571136
      size 932512
```

Dart's runtime stores **911KB of compiled application code** inside an `LC_NOTE`, a load command with no memory-mapping semantics that standard analysis tools skip and `strings` doesn't enumerate. I named this pattern **LC_NOTE Reflective Execution (LRE)**, a self-contained instance of MITRE ATT&CK T1620 (Reflective Code Loading) on macOS.

Where SEA wraps its payload in a named section that screams "look at me", LC_NOTE hides it in a container that has no name: no `NODE_SEA_BLOB`, no magic bytes, no 80MB file, just arbitrary data in an opaque load command. This is the negation: the wrapper does not betray the payload because there is no wrapper, and there is just the Mach-O format itself.

---

## Synthesis: Four Ways to Carry a Payload

I now have **four binaries** that carry the same logical payload, execute code and print a message, using four different containers.

### 1. SEA (Node.js)

```
$ node --experimental-sea-config sea-config.json
$ cp $(which node) sea-loader
$ npx postject sea-loader NODE_SEA_BLOB sea-prep.blob
$ ./sea-loader
PAYLOAD EXECUTED VIA SEA
```

**Binary:** 50MB, with `NODE_SEA_BLOB` section, `__NODE_SEA` segment, magic `20 DA 43 01`, instantly classifiable as SEA.

### 2. LRE Pure (ARM64 shellcode in LC_NOTE)

```
$ cc -o lre_pure stub.c -Wl,-headerpad,0x80
$ python3 lc_note_inject.py lre_pure payload.bin lre_final
$ ./lre_final
LRE OK!
```

**Binary:** 33KB, no named sections, no magic bytes, 17 imports (all standard libSystem). At runtime it reads its own binary, extracts raw ARM64 shellcode from `LC_NOTE` (`cmd = 0x31`, `data_owner = "lre..payload...."`), maps it with `mmap(RW)`, transitions to `mprotect(RX)`, and jumps, with **no dlopen, no /tmp, no entitlements, no decoding step**, an identical mechanism to Dart's `dartaotruntime`.

### 3. LRE+JS (QuickJS + JavaScript in LC_NOTE)

Like Dart, the JS engine lives in `__TEXT` and only the payload lives in LC_NOTE.

```
$ cc -o lre_js stub.c quickjs.o dtoa.o libregexp.o libunicode.o cutils.o
$ python3 lc_note_inject.py lre_js payload.js lre_final
$ ./lre_final
PAYLOAD FROM LC_NOTE via LRE+JS
```

**Binary:** 932KB, with QuickJS statically linked in the stub and the JavaScript payload carried in the LC_NOTE. At runtime it reads its own binary, extracts the JS from `LC_NOTE` (`cmd = 0x31`), and evaluates it via QuickJS, in the same PID with no `dlopen`, no `/tmp`, and no child process, structurally identical to how Dart loads its AOT snapshot from LC_NOTE.

### 4. Capability Cloaking (Runtime + Payload in LC_NOTE)

The LRE+JS PoC still has QuickJS in `__TEXT`, and a defender can see the engine, so the logical endpoint is moving the runtime itself into LC_NOTE.

```
$ cc -o lre_cloak stub.c -Wl,-headerpad,0x80
$ python3 lc_note_inject.py lre_cloak bundle+js.blob lre_final
$ ./lre_final
CAPABILITY CLOAKING: RUNTIME IN LC_NOTE
```

**Binary:** 1.1MB, split between a 34KB stub, of which the `__TEXT` segment is just 16KB with the rest being the Mach-O header and `__LINKEDIT`, and a 1MB LC_NOTE, where the LC_NOTE carries a QuickJS Mach-O bundle plus the JavaScript payload. At runtime the stub extracts the bundle, loads it entirely in memory, resolves its imports, and calls into it, while the `__TEXT` segment contains only a Mach-O parser: zero QuickJS symbols, zero QuickJS strings, zero payload strings in the stub, so the binary on disk does not reveal what it is capable of.

*(The loader is fully native: contiguous segment mapping, chained fixups parsing, and dlsym-based import resolution, no NSModule. Details in "The Loader" section below.)*

---

## Comparison

```
                   SEA            LRE Pure      LRE+JS         Cap. Cloaking
                   (Node.js)      (ARM64)       (QuickJS)      (Bundle)
─────────────────────────────────────────────────────────────────────────────
Size:              50MB           33KB          932KB          1.1MB
Payload:           JavaScript     ARM64 ASM     JavaScript     JavaScript
Runtime:           V8 in __TEXT   none          QuickJS __TEXT QuickJS LC_NOTE
Container:         NODE_SEA_BLOB  LC_NOTE 0x31  LC_NOTE 0x31   LC_NOTE 0x31
Section name:      fixed          none          none           none
Magic bytes:       20 DA 43 01    none          none           none
Named segment:     __NODE_SEA     none          none           none
Entitlements:      none           none          none           none
dlopen:            no             no            no             no
Execution:         same PID       same PID      same PID       same PID
Mechanism:         V8 interpret   mmap+mprotect QuickJS eval   in-memory load
YARA string-based: YES            NO            NO             NO ¹
```

---

*¹ "String-based" means rules anchored on fixed bytes like `NODE_SEA_BLOB`, magic `20 DA 43 01`, or a named section, while structural rules, a large `LC_NOTE` payload with a non-Apple `data_owner` or an anomalous `__TEXT`-to-file-size ratio, *do* catch the LRE variants. See Detection Guidance.*

### "Isn't LRE+JS Just a Smaller SEA?"

A skeptical reader might object at this point that LRE+JS has a JavaScript engine in `__TEXT`, a payload in a container, and executes inline, exactly like SEA, with the only visible difference being 50MB against 932KB, so is the size the only difference? It is a fair question, and the answer is no, because the difference is not quantitative but qualitative, and it is not about how big the wrapper is but about whether the wrapper has a name.

SEA's container is `NODE_SEA_BLOB`, a name that is fixed by the Node.js runtime and that an attacker cannot change, so a defender can write a YARA rule anchored on that name and catch every SEA binary ever produced: the name is the vulnerability. LRE+JS has no named wrapper, since the payload lives in `LC_NOTE` with a `data_owner` of the attacker's choosing, a name that can be random per build, and no YARA rule can anchor on a name that changes every time, so the attacker decides what the defender can signature on. This is the fundamental asymmetry: SEA gives the defender a fixed string, LRE gives the attacker the choice of what to expose, one is a fingerprint and the other is a blank slate, and the size difference is a symptom while the naming difference is the cause.

*(A second objection: the QuickJS engine still leaves strings in the binary, "EvalError", "Array", "function", a defender could signature on those, and it is true that these are generic JavaScript runtime strings that appear in every JS engine, benign or malicious, so signature on "EvalError" and you flag Electron apps, VS Code, and half the productivity software on macOS, making the signal-to-noise ratio useless as a detection rule.)*

---

### Capability Cloaking: Hiding the Runtime Itself

Addressing the string objection points toward a deeper question: the LRE+JS PoC still has QuickJS linked into `__TEXT`, which means the binary reveals its capability before it ever runs, because a defender looking at the import table and static strings can infer that this program embeds a JavaScript engine. What if we moved the runtime itself into LC_NOTE?

A JavaScript engine, or any language runtime, is inherently noisy, carrying thousands of symbols, error message strings, parsing tables, and standard library functions, and linking against `libc` for memory allocation, threading, and I/O, so when you statically link QuickJS into `__TEXT` you mix this noise into the binary's permanent identity and the resulting executable is architecturally "dirty", visibly, statically, irreversibly a JavaScript program. Now consider the alternative: the LC_NOTE contains not just the script but the entire QuickJS runtime, compiled as position-independent code with its imports resolved at load time, and the `__TEXT` segment shrinks to a single function, a Mach-O parser that reads its own binary, maps memory, and jumps, knowing nothing about JavaScript, having no opinion about what it carries, a blank slate.

I call this **Capability Cloaking**: the binary on disk reveals no capability, it is a generic bootstrap stub, and what it does, execute JavaScript, run shellcode, host a reverse shell, is determined entirely by the opaque blob in its LC_NOTE, decoded and assembled at runtime. The detection implications are severe: a YARA rule for "JavaScript engine" catches LRE+JS, where QuickJS is linked in `__TEXT`, but misses Capability Cloaking, where QuickJS is a blob in LC_NOTE, and the clean version can swap its payload between executions, running JavaScript today and Lua tomorrow, while the stub never changes and the capability is invisible until the moment of execution.

---

## The Loader: Chained Fixups and Contiguous Mapping

The Capability Cloaking binary uses a custom Mach-O loader that operates entirely in memory, and here is what it does and why it matters.

### From NSModule to Native

The first version of the Capability Cloaking PoC used `NSCreateObjectFileImageFromMemory` and `NSLinkModule`, deprecated macOS APIs from the 10.5 era that worked, but a production-grade loader should not depend on deprecated system calls, so the native loader replaces them with three pieces.

**1. Contiguous segment mapping.** dyld maps all segments of a dylib in a single contiguous allocation, preserving the VM layout, and the native loader does the same: scan all `LC_SEGMENT_64` commands, compute the total VM size, `mmap` one block, copy segment data, and apply per-segment `mprotect` protections, with no fragmented allocations and no address mismatches.

**2. Chained fixups parser.** Modern Mach-O binaries (macOS 13+) use `LC_DYLD_CHAINED_FIXUPS` instead of the legacy `LC_DYLD_INFO` bind and rebase opcodes, and in the chained fixups format each page of the `__DATA` segment contains a linked list of fixup entries, where each entry is a 64-bit word encoding whether it is a rebase (internal pointer adjustment) or a bind (external symbol resolution), the target offset or symbol ordinal, and a pointer to the next entry in the chain, and the parser walks these chains page by page, applying rebases and resolving imports.

**3. Import table parsing.** The chained fixups header points to a compact symbol table, where each import entry packs a library ordinal, a weak-import flag, and a name offset into a 32-bit word, and the symbol names are stored in a contiguous pool with a leading delimiter byte, and the parser extracts 143 imports for the QuickJS bundle and passes them to the symbol resolver.

The result: `NSCreateObjectFileImageFromMemory` and `NSLinkModule` are gone from the import table, and the loader is pure C99 and ARM64, operating on raw Mach-O bytes.

### The Last dyld Dependency

The native loader uses `dlsym(RTLD_DEFAULT, name)` for external symbol resolution, the only remaining dyld dependency, and replacing it requires walking the dyld shared cache's exports trie directly, a prefix tree that maps symbol names to addresses across all system libraries. The exports trie is parsable in theory, but in practice sub-images within the shared cache store their trie offsets relative to the cache base, which is accessible via `_dyld_get_shared_cache_range` yet the cache header format is undocumented, and resolving this is the next phase of the research.

---

## How `mmap` + `mprotect` Works Without Entitlements

The most important technical finding from this research is that Apple Silicon enforces W^X, meaning you cannot have a page that is simultaneously writable and executable, but **you CAN transition from writable to executable**.

```c
void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
memcpy(p, code, size);
mprotect(p, size, PROT_READ | PROT_EXEC);   // succeeds, no entitlement needed
((void(*)(void))p)();                         // executes
```

This works on macOS 26 (Darwin 25.5.0), I verified it, and the Dart runtime uses the exact same mechanism: map writable, copy from LC_NOTE, make executable, jump, with zero entitlements. **`MAP_JIT` and `com.apple.security.cs.allow-jit` are only needed for JIT compilers**, programs that write->execute->write->execute to the same page repeatedly, and a reflective loader that writes ONCE then executes forever does not need them.

---

## Entropy and Static Analysis

A defender might ask: even if the payload has no named section, can't you detect it by measuring entropy, since compressed or encrypted data has high entropy (close to 100%) while normal compiled code has lower entropy patterns, and a blob with 98% entropy in LC_NOTE would be suspicious regardless of what it is named? The bundle inside LC_NOTE is XOR-encoded with a single byte key, and since XOR preserves the exact entropy profile of the original data while rendering all readable strings invisible, the original QuickJS bundle has 80.2% entropy and after XOR it still has 80.2% entropy. For comparison:

| Binary | Entropy |
|--------|---------|
| `/bin/bash` | 80.7% |
| QuickJS bundle (original) | 80.2% |
| QuickJS bundle (XOR) | 80.2% |
| Capability Cloaking (bundle) | 80.4% |
| LRE+JS final binary | 82.4% |
| Zlib compressed | ~100% |

*(Values measured on the PoC binaries, macOS 26 / Darwin 25.5.0.)*

A zlib-compressed blob is flagged immediately by any entropy-based scanner, but an XOR-encoded blob is not, and the numbers matter: the QuickJS bundle, before and after XOR, sits at 80.2%, statistically indistinguishable from `/bin/bash` (80.7%), so whole-file entropy does not flag it. But whole-file entropy is the weak test, and the rest of the spectrum shows why: the LRE+JS binary measures 82.4%, *above* `/bin/bash`, because the engine in `__TEXT` is itself dense, while the Capability Cloaking binary, matching `/bin/bash` at 80.4%, carries **97% of its file inside a single `LC_NOTE`** with `__TEXT` being a 16KB stub, and a scanner that reads load-command structure, or even compares `__TEXT` size to file size, flags it without needing a single string. The honest claim is narrower and stronger: XOR defeats *byte-level* signatures, strings, magic bytes, section names, but it does not defeat *structural* analysis, and the payload's container, a declared `cmd 0x31` with a non-Apple `data_owner` and a disproportionate payload, is the high-signal surface that is exactly what Detection Guidance item 3 hunts for.

### Dynamic Key Derivation

A static XOR key sitting in `__TEXT` is a weakness, since an analyst with IDA or Hopper sees the de-XOR loop and extracts the key constant immediately, so the fix is to derive the key at runtime from something already present in the binary. The stub reads the LC_NOTE command from its own Mach-O header, and among the fields is `note->offset`, the file offset where the payload data begins, a value that changes with every build because it depends on the stub size, so the stub uses the low byte of this offset as the XOR key: `key = note->offset & 0xFF`. At injection time the same offset is known, so the blob is XOR-encoded with the matching key, and at runtime the stub reads the offset, derives the key, and de-XORs, with no constant existing in `__TEXT` that reveals the key, meaning an analyst must reverse-engineer the derivation logic and compute the key from the binary's own structure.

The JS payload is decrypted in-place: the bytes in the LC_NOTE buffer are XOR'd directly, passed to QuickJS for evaluation, and then overwritten with zeros, so the plaintext exists in RAM only for the duration of `JS_Eval`. There is a nuance here worth addressing: naive section-based scanners fail because tools that only inspect executable sections or known tables like `__cstring` ignore LC_NOTE entirely, the payload sits outside their visibility window, but global YARA rules catch it, since if an analyst runs a YARA rule that searches the entire binary without scoping to a specific section, the raw strings inside the XOR-encoded bundle will not match, however the loader stub contains the de-XOR loop, and the original bundle if left unencoded would be found, so the XOR encoding closes this gap: a YARA rule anchored on `$string in (__TEXT,__cstring)` sees nothing because the LC_NOTE is not a section, and a YARA rule scanning the whole file sees nothing because the strings are XOR-encoded at rest.

---

## Detection Guidance

For SEA the existing YARA rules for `NODE_SEA_BLOB`, `__NODE_SEA`, and magic `20 DA 43 01` continue to work, so keep them deployed, but for LRE-based techniques static IoCs are insufficient and defenders should:

1. **Monitor `mprotect` calls that add `PROT_EXEC`.** A RW->RX transition on anonymous memory is rare, and this is the highest-signal behavior indicator.
2. **Look for self-reading binaries.** A process that `open`s its own executable and reads from non-standard offsets is suspicious.
3. **Hunt for `LC_NOTE` (`cmd = 0x31`) with large payloads.** If you control the build pipeline, scan Mach-O binaries for load command `0x31` with non-Apple `data_owner` values.
4. **Watch for the absence of expected events.** Network or file I/O without a corresponding `ES_EVENT_TYPE_NOTIFY_EXEC` means activity is happening in a process you didn't see start.
5. **Monitor for chained fixup walkers.** The native loader walks `LC_DYLD_CHAINED_FIXUPS` page by page, and a process that accesses its `__DATA` segment through this pattern is anomalous.
6. **Dynamic analysis sees nothing at the process level.** No `fork`, no `execve`, no `posix_spawn`, so `ES_EVENT_TYPE_AUTH_EXEC` never fires and an EDR that correlates behavior to new process creation is blind to this execution; the evasion is precise, defeating process-creation telemetry rather than memory forensics, which a sensor monitoring `mprotect` RW->RX transitions or scanning process memory could still observe.
7. **Check import tables for `_dlsym` in small binaries.** A stub that imports `_dlsym` alongside `_mmap`, `_mprotect`, `_open`, and `_fstat` carries the signature of an in-memory loader, since ordinary binaries of that size rarely resolve symbols at runtime, and the exports-trie walker exists precisely to remove that last visible resolution symbol.

## Gatekeeper Complacency

There is one more property worth noting: the LC_NOTE is part of the Mach-O file structure, it participates in the binary's offset layout and is covered by `LC_CODE_SIGNATURE`, and since the code signature hashes the entire file, the injected payload is included in that hash, so ad-hoc sign the binary after injection and macOS accepts it. Two qualifications keep that claim honest.

First, Apple's structural validation is real: `codesign` rejects binaries with data past the contents of the last load command, "no junk past end of file", and LC_NOTE is not junk, it is a *declared* load command with `offset` and `size` pointing inside the file, and that declared-ness is exactly why it survives validation where a naively appended payload would not. Second, the claim holds for locally-built or non-quarantined binaries, since a binary that carries the quarantine attribute goes through Gatekeeper's notarization check, which an ad-hoc signature does not satisfy, and re-signing ad-hoc discards the original signing identity, so the result is no longer Apple- or Developer-ID-signed, only trusted on machines that already trust it. Within those bounds the point stands: packers, injectors, and cryptors typically break the code signature, forcing the binary to be stripped, resigned, or run with SIP exceptions, while LC_NOTE payload embedding introduces no such violation, and the binary remains structurally and cryptographically valid under local execution.

---

## Repository

Full source for all PoCs at **[github.com/machinecase/lre-injector](https://github.com/machinecase/lre-injector)**, including stub loaders, the LC_NOTE injector, payload generators, the QuickJS bundle build, the native Mach-O loader with chained fixups support, and the direct symbol resolver prototype.

### Future Work

Three directions extend this research:

1. **Shared cache exports trie parser.** Replacing the last `dlsym` call requires parsing the dyld shared cache's centralized exports trie, whose cache base is accessible via `_dyld_get_shared_cache_range`, and the remaining work is parsing the `CacheImageInfoExtra` structures to locate each sub-image's trie offset within the cache.
2. **ARM64e support.** The chained fixups parser currently handles `DYLD_CHAINED_PTR_64_OFFSET` (format 6), and adding `DYLD_CHAINED_PTR_ARM64E_USERLAND` (format 9) would support pointer-authenticated binaries.
3. **Cross-runtime payload.** The Capability Cloaking architecture is runtime-agnostic, since the same LC_NOTE container can carry Lua, Python (via MicroPython), or native ARM64 shellcode, and building a minimal bootstrapper that auto-detects the payload format would generalize the technique.

---

*Part 3 of the series.*  
*[Part 1: SEA Defense Evasion](/posts/sea-node-defenseEvasion/) · [Part 2: Reversing Dart AOT on macOS](/posts/dart-reverse-macos/)*
