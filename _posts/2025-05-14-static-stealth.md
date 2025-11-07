---
title: Static Stealth Syscalls on macOS x86-64
date: 2025-05-14 16:30:00 +0300
categories: [Malware Analysis]
tags: [Assembly, Stealth, Reversing, macOS]
image: "https://recreio.com.br/wp-content/uploads/2024/10/coringa-hqcapa.jpg"
---

# Static stealth syscalls on macOS x86-64, from an assembly point of view

This post looks at a static stealth syscall pattern on macOS x86-64 from an assembly mindset. I explain the idea in plain language, show safe neutralized snippets so you can see how the pieces fit, and share practical tips defenders can use to spot and stop this behavior. There is no runnable code here, only conceptual pseudocode and detection notes. A real working variant for dynamic codegen would need special JIT permissions or entitlements and would likely be flagged and quarantined by modern security tools. This sample does not rely on JIT because it keeps the syscall instruction in `.text`.

## Why this matters

Stealth syscalls try to hide or delay obvious static indicators. The syscall numbers do not sit in the code section and a small indirection layer makes simple pattern scans less effective. In shared hosting and on endpoints, that can make malicious loaders and persistence harder to catch with naive static rules.

Examples
• loader that stores syscall numbers as XORed qwords in `.data`
• tiny wrappers that decode just in time and then execute `syscall`
• a logical map that shuffles indices so the table is not referenced linearly

<details>
  <summary><strong>CODE (NASM, macOS x86-64)</strong></summary>
  <pre><code class="language-nasm">

%define SYS_close  0x2000006
%define SYS_open   0x2000005
%define SYS_execve 0x200003b
%define SYS_write  0x2000004
%define SYS_exit   0x2000001
%define XOR_KEY    0xAABBCCDDEEFF0011

%define O_CREAT    0x200 
%define O_WRONLY   0x1  
%define O_TRUNC    0x400 
section .text
    global _start
    default rel 

_execve:
    movzx r9, byte [r14 + 0] 
    xor r9, 0x5A 
    mov rax, [r13 + r9*8]
    xor rax, XOR_KEY 
    syscall
    ret

_open:
    movzx r9, byte [r14 + 1] 
    xor r9, 0x5A 
    mov rax, [r13 + r9*8]
    xor rax, XOR_KEY         ; RAX = SYS_open
    syscall
    ret

_write:
    movzx r9, byte [r14 + 2] 
    xor r9, 0x5A 
    mov rax, [r13 + r9*8]
    xor rax, XOR_KEY         ; RAX = SYS_write
    syscall
    ret

_close:
    movzx r9, byte [r14 + 3] 
    xor r9, 0x5A   
    mov rax, [r13 + r9*8]
    xor rax, XOR_KEY 
    syscall
    ret
    
_start:
    lea r13, [rel syscall_table]
    lea r14, [rel logical_map] 
    
    
    xor rax, rax
    push rax 
    mov rbx, 0x7478742e74736574 ; "test.txt"
    push rbx
    lea rdi, [rsp]
    
    mov rsi, O_CREAT | O_WRONLY | O_TRUNC ; RSI = Flags
    mov rdx, 0o644
    
    call _open  
    mov r15, rax  
    
    mov rax, 0x0a68746c61657473 ; "sth\n"
    push rax
    mov rax, 0x206d6f7266206f6c ; "lo from "
    push rax
    mov rax, 0x6c6548          ; "Hel" 
    push rax
    
    mov rdi, r15 
    lea rsi, [rsp] 
    mov rdx, 21        
    
    call _write                 
    add rsp, 24   
    
    mov rdi, r15
    call _close

    
    xor rax, rax
    push rax
    mov rbx, 0x736c2f6e69622f  ; "/bin/ls"
    push rbx
    mov rdi, rsp   

    push rax
    push rdi 
    mov rsi, rsp    
    
    mov rdx, rax 

    call _execve    
    
    
    xor rdi, rdi 
    mov rax, SYS_exit
    syscall                     
    
    
section .data    
    syscall_table:
        dq SYS_close ^ XOR_KEY  
        dq SYS_open ^ XOR_KEY  
        dq SYS_execve ^ XOR_KEY 
        dq SYS_write ^ XOR_KEY 


    logical_map:
        db 0x58 ; Execve -> 2
        db 0x5B ; Open -> 1
        db 0x59 ; Write -> 3
        db 0x5A ; Close -> 0

  </code></pre>
</details>

## The idea at a glance

Instead of embedding syscall numbers as clear constants in `.text`, keep them in a table in `.data` and encode them with a trivial transform such as XOR. At runtime, a wrapper reads a one-byte map entry, unmasks it to a real index, loads an encoded qword from the table, decodes it to recover the real syscall number into `RAX`, then executes `syscall`.

# The table and the logical map

• `syscall_table` keeps the real syscall numbers encoded as XORed qwords
• `logical_map` is a tiny byte array that hides which table slot the wrapper will use
• at runtime the wrapper reads one byte from `logical_map`, XORs it with `0x5A` to get a real index, loads the encoded qword from `syscall_table[index]`, decodes it by XOR with `XOR_KEY`, and places the result into `RAX`

Your data region, annotated

```nasm
syscall_table:
    dq SYS_close ^ XOR_KEY     ; index 0
    dq SYS_open  ^ XOR_KEY     ; index 1
    dq SYS_execve ^ XOR_KEY    ; index 2
    dq SYS_write ^ XOR_KEY     ; index 3

logical_map:
    db 0x58    ; for execve
    db 0x5B    ; for open
    db 0x59    ; for write
    db 0x5A    ; for close
```

How the map bytes become real indices
The wrappers do `xor r9, 0x5A` after loading a byte from `logical_map`. That operation turns the obfuscated offset into the real table index.
• `0x58 ^ 0x5A = 0x02` so execve uses table index 2
• `0x5B ^ 0x5A = 0x01` so open uses table index 1
• `0x59 ^ 0x5A = 0x03` so write uses table index 3
• `0x5A ^ 0x5A = 0x00` so close uses table index 0

Neutralized wrapper flow for clarity

```nasm
; r13 -> syscall_table
; r14 -> logical_map

WRAP_GENERIC:
    movzx  r9,  byte [r14 + LOGICAL_OFFSET]
    xor    r9,  0x5A
    mov    rax, [r13 + r9*8]
    xor    rax, XOR_KEY  
    syscall
    ret
```

Interactive checks for your readers
• ask them what table slot the open wrapper will hit after the XOR step
answer is index 1 because `0x5B ^ 0x5A = 0x01`
• ask them what value lands in `RAX` right before `syscall` in the write wrapper
answer is `SYS_write` after `xor rax, XOR_KEY`

Why this helps the attacker
• the obvious `0x2000xxx` syscall numbers do not appear as plain constants near the call sites in `.text`
• the table indirection and the one byte XOR in the map make linear pattern scans less reliable

What a defender can key on
• very small map in `.data` read by multiple tiny wrappers
• repeated sequence read byte, XOR with a single byte immediate, load qword from a nearby table, XOR with a fixed 64 bit immediate, then `syscall`
• correlation with file operations and process creation around those wrappers

How to extend or reshuffle
• to add a new syscall, push `dq SYS_new ^ XOR_KEY` to the table and add a matching byte in `logical_map` that XORs with `0x5A` to the intended index
• to reshuffle, change the map bytes so the same wrappers point to different indices without touching the table layout

Short takeaway
The stealth here lives in data. A tiny map plus a fixed key moves the syscall identity out of easy static view, but the decode then use rhythm at runtime remains consistent and is exactly what good telemetry can catch.


## Walkthrough mapped to the sample

Symbols and roles
• `r13` points to `syscall_table` in `.data`
• `r14` points to `logical_map` in `.data`
• `XOR_KEY` encodes and decodes syscall numbers
• wrappers read a map byte, unmask it with `xor r9, 0x5A`, index `r13 + r9*8`, decode with `xor rax, XOR_KEY`, then `syscall`

Open
The program pushes `"test.txt"`, sets `O_CREAT | O_WRONLY | O_TRUNC`, mode `0644`, then calls `_open`. Inside `_open`, the map byte at `[r14+1]` unmasks to 1 and selects `SYS_open ^ XOR_KEY`. After decode, `rax = SYS_open` and `syscall` runs. The returned file descriptor is saved in `r15`.

Write
The program builds `"Hello from stealth\n"` on the stack, sets `rdi = fd`, `rsi = buf`, `rdx = 21`, then calls `_write`. The map byte at `[r14+2]` unmasks to 3 and selects `SYS_write`. After decode, `rax = SYS_write`, then `syscall`. The stack is cleaned up.

Close
It sets `rdi = fd` and calls `_close`. The map byte at `[r14+3]` unmasks to 0 and selects `SYS_close`. After decode, `rax = SYS_close`, then `syscall`.

Execve
It pushes `"/bin/ls"`, builds `argv = { "/bin/ls", NULL }`, sets `envp = NULL`, then calls `_execve`. The map byte at `[r14+0]` unmasks to 2 and selects `SYS_execve`. After decode, `rax = SYS_execve`, then `syscall`. If it returns, the code falls back to `SYS_exit`.

## Why this is “static” stealth

The `syscall` instruction remains in `.text`. No RWX allocations, no runtime code emission. The stealth comes from data indirection and XOR. Static scanners see fewer obvious constants, but the runtime rhythm is stable and detectable.

What attackers gain

• fewer obvious constants in `.text`.

• a layer of indirection that breaks naive pattern scans.


What they pay

• a fixed 64-bit key in the binary.

• a tiny data layout that can be recognized.

• a repeatable decode-then-use rhythm around `RAX` and `syscall`.

## Detection that works in practice

Static hints

• small wrappers that read a byte from `.data`, XOR with a single-byte immediate, index a table of qwords, XOR the qword with a fixed 64-bit immediate, then end with `syscall; ret`.

• presence of a very small map table and a small array of qwords near a constant 64-bit key.

Runtime hints

• repeated syscalls from the same tiny wrapper addresses in `.text`.

• immediate reads from a small `.data` area just before each syscall.

• a qword load followed by a 64-bit XOR immediate, then a syscall using the result in `RAX`.

• correlation with I/O or process creation that follows the wrappers.

Hunting ideas

• record the instruction pointer on `sys_enter` and group by small wrapper addresses.

• look back a few instructions for reads from a small `.data` region and a 64-bit XOR immediate before `syscall`.

• correlate with file writes to new paths or with `execve` into common utilities like `/bin/ls`.

## macOS specifics relevant to this code

• syscall number goes in `RAX` and uses the macOS numbering such as `0x2000004` for `write`.

• arguments follow the usual x86-64 macOS syscall convention in registers.

• no JIT entitlement is necessary for this static pattern because it does not create executable pages at runtime.

Related note on JIT and entitlements
If you were dynamically generating code, macOS Hardened Runtime expects proper signing with the JIT entitlement and use of `MAP_JIT` plus `pthread_jit_write_protect_np` to flip between write and execute. That is out of scope here, but it matters for defenders because legitimate JITs have a distinct telemetry shape compared to static patterns like this.

## Cutting false positives

Legitimate software that decodes tables at runtime exists, but the decode-then-use directly into `RAX` for `syscall` is a strong tell.

Ideas

• treat signed system runtimes and known JIT processes differently.

• require at least two strong signals together, for example decode-then-use plus file write or process creation.

• consider short time windows so a tight decode-then-syscall pattern is not lost in background noise.

## Short FAQ

Does this require JIT entitlements?

No. The sample executes `syscall` from `.text` and does not allocate or execute from RWX memory.

What breaks the stealth here
Runtime correlation. The small wrapper rhythm is consistent. Load map byte, unmask, load qword, XOR decode, move to `RAX`, `syscall`. Pair that with nearby file or process activity.

What is the main tradeoff
You remove obvious constants from `.text`, but add a recognizable data layout and a fixed key. The behavior over time becomes a reliable signal.


## Closing

Static stealth syscall tricks move obvious clues out of easy view, but they keep a steady runtime melody. If you watch for the little wrapper pattern and correlate it with file and process actions, you can catch most variants without chasing every byte-level change.

# Final note, being honest: you can stuff the wrappers with “junk”, some useless math, a few decorative leas, maybe a loop that does nothing, just to pose as a legitimate function and hide the real intent. But at runtime the melody gives it away: read the map, XOR, load the qword, XOR again, drop it into RAX and then syscall. The rest is makeup. And makeup, as we know back in Gotham, doesn’t change the smile.


---