// cainj.cpp — Overwatch 1.74.0.0 (104319) preservation shim  (v31)

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#define ENABLE_HWBP 0

#if ENABLE_HWBP
#include <tlhelp32.h>
#endif

typedef unsigned long long u64;
typedef unsigned int       u32;

// ----------------------------------------------------------------------------
static const u64 RVA_PARSE     = 0x2370090ULL;
static const u64 RVA_ADD_CERT  = 0x2385AE0ULL;
static const u64 RVA_VERIFY    = 0x23816F0ULL;
static const u64 RVA_WRAP_VTBL = 0x2A617D0ULL;
static const u64 TEXT_HI_RVA   = 0x25B3808ULL;

static const u64 CLUSTER_LO    = 0x2385000ULL;
static const u64 CLUSTER_HI    = 0x2386800ULL;

static const size_t WRAP_STORE_OFF = 0x20;
static const size_t WRAP_VMODE_OFF = 0x94;

static const int    MAX_WRAP    = 32;
static const u64    SCAN_BUDGET = 4000ULL;
static const u64    REGION_CAP  = 0x8000000ULL;
static const char*  PEM_PATH =
    "CHANGE TO YOUR DESIRED PATH";

static const int DIAG_MAX_ROUNDS = 2;
static const u64 BFS_OBJ_BYTES   = 0x200;
static const u64 CTX_DUMP_BYTES  = 0x200;
static const int BFS_MAX_VISIT   = 64;

// ---- v31 store-ref collector tuning ---------------------------------------
static const int  SR_MAX_ROUNDS = 3;       // bounded (anti-hang; no 2nd unbounded scan)
static const u64  STORE_WIN      = 0x100;   // ± window dumped around each store-field
static const int  SR_MAX_FIELDS  = 64;      // cap store-field hits per round
// Phase toggle. Leave false for observe. In Phase B set true AND set
// g_cbDelta to the confirmed [store + delta] offset seen in Phase A logs.
static bool       g_nullCallback = false;
static long long  g_cbDelta      = 0x7fffffffLL; // disabled sentinel

typedef void* (*parse_fn)(const char*);
typedef int   (*add_fn)(void*, void*);

// ----------------------------------------------------------------------------
static u64  g_base = 0, g_imgLo = 0, g_imgHi = 0, g_code = 0, g_textHi = 0;
static u64  g_wrapVtbl = 0;
static u64  g_storeAddr = 0;

static void* g_wrap[MAX_WRAP];
static int   g_wrapN = 0;

static long  g_vmodeWrites = 0, g_appVerifyWrites = 0, g_pageFaults = 0, g_skipBig = 0;
static int   g_diagRounds = 0;

static u64   g_visited[BFS_MAX_VISIT];
static int   g_visitedN = 0;

static int   g_srRounds = 0;         // v31
static long  g_ctxCbWrites = 0;      // v31

static char  g_pem[8192];
static int   g_pemLen = 0;

// ----------------------------------------------------------------------------
static void L(const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap); va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    char line[1100];
    _snprintf(line, sizeof(line) - 1, "[cainj] %s", buf);
    line[sizeof(line) - 1] = 0;
    OutputDebugStringA(line);
}

// ----------------------------------------------------------------------------
static void computeImage() {
    g_base = (u64)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)g_base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    g_imgLo = g_base;
    g_imgHi = g_base + nt->OptionalHeader.SizeOfImage;
    g_code  = g_base + 0x1000;
    g_textHi = g_base + TEXT_HI_RVA;
    g_wrapVtbl = g_base + RVA_WRAP_VTBL;
}

static inline bool inImage(u64 p) { return p >= g_imgLo && p < g_imgHi; }
static inline bool inCode(u64 p)  { return p >= g_code && p < g_textHi; }

static bool readable(u64 p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
    u64 end = (u64)mbi.BaseAddress + mbi.RegionSize;
    return (p + n) <= end;
}

static u64 rd64(u64 p) {
    __try { return *(volatile u64*)p; }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_pageFaults); return 0; }
}
static u32 rd32(u64 p) {
    __try { return *(volatile u32*)p; }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_pageFaults); return 0; }
}
static bool wr32(u64 p, u32 v) {
    __try { *(volatile u32*)p = v; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_pageFaults); return false; }
}
static bool wr64(u64 p, u64 v) {   // v31: data-only 8-byte write for callback slot
    __try { *(volatile u64*)p = v; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_pageFaults); return false; }
}

// ----------------------------------------------------------------------------
static bool loadPEM() {
    FILE* f = fopen(PEM_PATH, "rb");
    if (!f) { L("PEM open FAILED: %s", PEM_PATH); return false; }
    g_pemLen = (int)fread(g_pem, 1, sizeof(g_pem) - 1, f);
    fclose(f);
    if (g_pemLen <= 0) { L("PEM empty"); return false; }
    g_pem[g_pemLen] = 0;
    L("PEM loaded %d bytes", g_pemLen);
    return true;
}

static void* parseCA() {
    parse_fn parse = (parse_fn)(g_base + RVA_PARSE);
    void* ca = NULL;
    __try { ca = parse(g_pem); }
    __except (EXCEPTION_EXECUTE_HANDLER) { L("parseCA threw"); return NULL; }
    return ca;
}

// ----------------------------------------------------------------------------
static bool looksLikeStore(u64 store) {
    if (!store || (store & 7)) return false;
    if (!readable(store, 0x18)) return false;
    u64 stk = rd64(store + 0x08);
    if (!stk || (stk & 7) || !readable(stk, 0x20)) return false;
    u32 num = rd32(stk + 0x00);
    if (num > 0x10000) return false;
    u64 comp = rd64(stk + 0x18);
    if (!inImage(comp)) return false;
    u64 crva = comp - g_base;
    return (crva >= CLUSTER_LO && crva < CLUSTER_HI);
}

static bool isWrapper(u64 obj) {
    if (!obj || (obj & 7)) return false;
    if (!readable(obj, WRAP_VMODE_OFF + 4)) return false;
    return rd64(obj + 0x00) == g_wrapVtbl;
}

static void tag(u64 v, char* out, size_t n) {
    if (v == g_storeAddr && g_storeAddr) _snprintf(out, n - 1, "==STORE");
    else if (inCode(v))  _snprintf(out, n - 1, "IMG-CODE rva=0x%llx", (unsigned long long)(v - g_base));
    else if (inImage(v)) _snprintf(out, n - 1, "IMG-DATA rva=0x%llx", (unsigned long long)(v - g_base));
    else if (v && !(v & 7) && readable(v, 8)) _snprintf(out, n - 1, "HEAP");
    else out[0] = 0;
    out[n - 1] = 0;
}

static int findStorePtr(u64 obj) {
    for (u64 o = 0; o + 8 <= BFS_OBJ_BYTES; o += 8)
        if (rd64(obj + o) == g_storeAddr) return (int)o;
    return -1;
}

static void dumpCtx(u64 ctx, int storeOff, int depth, u64 parent) {
    L(">> RAW SSL_CTX FOUND @ %016llX (depth=%d parent=%016llX) cert_store at ctx+0x%x",
      (unsigned long long)ctx, depth, (unsigned long long)parent, storeOff);
    if (!readable(ctx, CTX_DUMP_BYTES)) { L("   (ctx not fully readable)"); return; }
    for (u64 o = 0; o + 8 <= CTX_DUMP_BYTES; o += 8) {
        u64 v = rd64(ctx + o);
        char t[64]; tag(v, t, sizeof(t));
        bool hot = (o >= 0x80 && o <= 0xB0);
        if (t[0] || hot)
            L("   ctx+0x%03llx = %016llX  %s%s",
              (unsigned long long)o, (unsigned long long)v, t,
              hot ? "  <== verify-config window" : "");
    }
}

static bool bfsForCtx(u64 wrap) {
    g_visitedN = 0;
    u64 q[BFS_MAX_VISIT]; int qd[BFS_MAX_VISIT];
    int head = 0, tail = 0;
    for (u64 o = 0; o + 8 <= BFS_OBJ_BYTES; o += 8) {
        u64 v = rd64(wrap + o);
        if (v && !(v & 7) && !inImage(v) && v != wrap && v != g_storeAddr && readable(v, 0x20)) {
            if (tail < BFS_MAX_VISIT) { q[tail] = v; qd[tail] = 1; tail++; }
        }
    }
    while (head < tail && g_visitedN < BFS_MAX_VISIT) {
        u64 obj = q[head]; int depth = qd[head]; head++;
        bool seen = false;
        for (int i = 0; i < g_visitedN; i++) if (g_visited[i] == obj) { seen = true; break; }
        if (seen) continue;
        g_visited[g_visitedN++] = obj;
        if (!readable(obj, BFS_OBJ_BYTES)) continue;
        int so = findStorePtr(obj);
        if (so >= 0) { dumpCtx(obj, so, depth, wrap); return true; }
        if (depth < 2) {
            for (u64 o = 0; o + 8 <= BFS_OBJ_BYTES; o += 8) {
                u64 v = rd64(obj + o);
                if (v && !(v & 7) && !inImage(v) && v != g_storeAddr && readable(v, 0x20)) {
                    if (tail < BFS_MAX_VISIT) { q[tail] = v; qd[tail] = depth + 1; tail++; }
                }
            }
        }
    }
    return false;
}

static void diagWrapper(u64 wrap) {
    if (g_diagRounds >= DIAG_MAX_ROUNDS) return;
    if (!readable(wrap, BFS_OBJ_BYTES)) return;
    g_diagRounds++;
    L("=== BFS ctx-hunt from wrapper %016llX (round %d/%d) store=%016llX ===",
      (unsigned long long)wrap, g_diagRounds, DIAG_MAX_ROUNDS,
      (unsigned long long)g_storeAddr);
    bool found = bfsForCtx(wrap);
    if (!found)
        L("   NO object within depth<=2 holds cert_store==store (visited=%d) "
          "=> pin is likely a C++ wrapper virtual method, not an OpenSSL app_verify_callback",
          g_visitedN);
    L("=== BFS end (visited=%d) ===", g_visitedN);
}

// ---- v31: dump game-code pointers near a heap qword == store ---------------
// Does NOT guess an object base. Logs only pointers into the game's .text
// (inCode), which structurally excludes stack return-addresses (ntdll/kbase)
// and rdata descriptors. Reveals the app_verify_callback's offset RELATIVE to
// the store field directly, so Phase B can null exactly that data slot.
static void inspectStoreField(u64 A) {
    bool any = false;
    for (long long d = -(long long)STORE_WIN; d <= (long long)STORE_WIN; d += 8) {
        u64 p = A + d;
        if (!readable(p, 8)) continue;
        u64 v = rd64(p);
        if (!inCode(v)) continue;              // game .text only -> kills false positives
        if (!any) {
            L("STORE-REF @ %016llX (heap store-field) game-code neighbors:", (unsigned long long)A);
            any = true;
        }
        L("   [store%+lld] @ %016llX = %016llX IMG-CODE rva=0x%llx",
          d, (unsigned long long)p, (unsigned long long)v, (unsigned long long)(v - g_base));
        if (g_nullCallback && d == g_cbDelta) {
            if (wr64(p, 0)) {
                InterlockedIncrement(&g_ctxCbWrites);
                L("   ** app_verify_callback NULLed @ %016llX (writes=%ld) **",
                  (unsigned long long)p, g_ctxCbWrites);
            }
        }
    }
}

// ---- v31: bounded heap walk collecting store back-references ---------------
// Reuses v30's EXACT region gating (commit && rw && !guard && !inImage &&
// size<=REGION_CAP). Bounded to SR_MAX_ROUNDS total -> no RUN-15 double-scan hang.
static void collectStoreRefs() {
    if (!g_storeAddr) return;
    if (g_srRounds >= SR_MAX_ROUNDS) return;
    g_srRounds++;
    L("=== store-ref collect (round %d/%d) store=%016llX nullCb=%d cbDelta=%lld ===",
      g_srRounds, SR_MAX_ROUNDS, (unsigned long long)g_storeAddr,
      g_nullCallback ? 1 : 0, g_cbDelta);
    int fields = 0;
    MEMORY_BASIC_INFORMATION mbi;
    u64 addr = 0x10000ULL, budget = 0;
    while (addr < g_imgHi + 0x40000000ULL && budget < SCAN_BUDGET) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        u64 rsz = (u64)mbi.RegionSize, rbase = (u64)mbi.BaseAddress;
        budget++;
        bool commit = (mbi.State == MEM_COMMIT);
        DWORD prot = mbi.Protect & 0xFF;
        bool rw = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE);
        bool guard = (mbi.Protect & PAGE_GUARD) != 0;
        if (commit && rw && !guard && !inImage(rbase)) {
            if (rsz > REGION_CAP) InterlockedIncrement(&g_skipBig);
            else {
                __try {
                    for (u64 p = rbase; p + 8 <= rbase + rsz; p += 8) {
                        if (*(volatile u64*)p == g_storeAddr) {
                            inspectStoreField(p);
                            if (++fields >= SR_MAX_FIELDS) break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_pageFaults); }
            }
        }
        if (fields >= SR_MAX_FIELDS) break;
        addr = rbase + rsz;
    }
    L("=== store-ref end (fields=%d ctxCbWrites=%ld) ===", fields, g_ctxCbWrites);
}

// ----------------------------------------------------------------------------
static void scanPage(u64 lo, u64 hi, void** out, int* outN) {
    for (u64 p = lo; p + 8 <= hi; p += 8) {
        u64 v = *(volatile u64*)p;
        if (v == g_wrapVtbl) {
            if (isWrapper(p) && *outN < MAX_WRAP) out[(*outN)++] = (void*)p;
        }
    }
}
static void scanRegion(u64 lo, u64 hi, void** out, int* outN) {
    __try { scanPage(lo, hi, out, outN); }
    __except (EXCEPTION_EXECUTE_HANDLER) { InterlockedIncrement(&g_pageFaults); }
}

static int scanCollect(void** out, int cap) {
    int n = 0;
    MEMORY_BASIC_INFORMATION mbi;
    u64 addr = 0x10000ULL, budget = 0;
    while (addr < g_imgHi + 0x40000000ULL && budget < SCAN_BUDGET) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        u64 rsz = (u64)mbi.RegionSize, rbase = (u64)mbi.BaseAddress;
        budget++;
        bool commit = (mbi.State == MEM_COMMIT);
        DWORD prot = mbi.Protect & 0xFF;
        bool rw = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE);
        bool guard = (mbi.Protect & PAGE_GUARD) != 0;
        if (commit && rw && !guard && !inImage(rbase)) {
            if (rsz > REGION_CAP) InterlockedIncrement(&g_skipBig);
            else scanRegion(rbase, rbase + rsz, out, &n);
        }
        addr = rbase + rsz;
        if (n >= cap) break;
    }
    return n;
}

// ----------------------------------------------------------------------------
static void tryAddAndNeutralize(void* ourCA, int scanIdx) {
    add_fn add = (add_fn)(g_base + RVA_ADD_CERT);
    for (int i = 0; i < g_wrapN; i++) {
        u64 wrap  = (u64)g_wrap[i];
        u64 store = rd64(wrap + WRAP_STORE_OFF);
        if (!looksLikeStore(store)) continue;

        g_storeAddr = store;

        u64 stk = rd64(store + 0x08);
        u32 before = rd32(stk + 0x00);
        u64 comp = rd64(stk + 0x18);
        int ok = 0;
        __try { ok = add((void*)store, ourCA); }
        __except (EXCEPTION_EXECUTE_HANDLER) { L("add threw (store freed?)"); continue; }
        u32 after = rd32(stk + 0x00);
        L("*** CA ADDED *** store=%016llX num %u->%u compRVA=0x%llx",
          (unsigned long long)store, before, after, (unsigned long long)(comp - g_base));

        u32 vm = rd32(wrap + WRAP_VMODE_OFF);
        if (vm != 0xFFFFFFFEu && vm != 0) {
            if (wr32(wrap + WRAP_VMODE_OFF, 0)) {
                InterlockedIncrement(&g_vmodeWrites);
                L("** WRAPPER %016llX verify_mode +0x94: %u -> 0 ** (writes=%ld)",
                  (unsigned long long)wrap, vm, g_vmodeWrites);
            }
        }

        diagWrapper(wrap);
        (void)ok; (void)scanIdx;
    }
}

// ----------------------------------------------------------------------------
static DWORD WINAPI worker(LPVOID) {
    computeImage();
    L("v31 base=%016llX vtbl=%016llX hwbp=%d nullCb=%d (CA-add + verify_mode + heap store-ref collector)",
      (unsigned long long)g_base, (unsigned long long)g_wrapVtbl, ENABLE_HWBP, g_nullCallback ? 1 : 0);

    if (!loadPEM()) return 0;
    void* ourCA = parseCA();
    L("ourCA=%016llX", (unsigned long long)ourCA);
    if (!ourCA) return 0;

    for (int scanIdx = 0; ; scanIdx++) {
        g_wrapN = 0;
        g_wrapN = scanCollect(g_wrap, MAX_WRAP);
        tryAddAndNeutralize(ourCA, scanIdx);
        collectStoreRefs();                 // v31: bounded, runs after store is known
        if ((scanIdx & 7) == 0 || g_wrapN > 0) {
            L("scan#%d wrappers=%d vmodeWrites=%ld appVerifyWrites=%ld faults=%ld skipBig=%ld diag=%d srRounds=%d ctxCbWrites=%ld",
              scanIdx, g_wrapN, g_vmodeWrites, g_appVerifyWrites, g_pageFaults, g_skipBig,
              g_diagRounds, g_srRounds, g_ctxCbWrites);
        }
        Sleep(250);
    }
    return 0;
}

// ----------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
