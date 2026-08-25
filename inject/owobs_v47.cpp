// owobs_v47.cpp - tournament mode token tap
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <limits.h>

// ---------------------------------------------------------------------------
static bool      g_dumpCode       = true;
static uint32_t  g_startDelayMs   = 15000;
static bool      g_walkPendingMap = true;
static uintptr_t g_managerAddr    = 0;
static uint32_t  g_normalPollMs   = 200;   // slow poll when idle
static uint32_t  g_fastPollMs     = 20;    // fast poll once 0x98 fires
static uint32_t  g_fastPollBudget = 80;    // max fast-poll iterations (~1.6s)

static const char* PENDING_KEY_FILE =
    "CHANGE TO YOUR DESIRED PATH";
static const char* LOG_PATH =
    "CHANGE TO YOUR DESIRED PATH";

// RVAs (1.74 build 104319)
static const uintptr_t VTABLE_WIN_LO         = 0x26160A0;
static const uintptr_t VTABLE_WIN_HI         = 0x26162A0;
static const uintptr_t SESSION_VTBL          = 0x2616260;
static const uint32_t  STATE_OFF             = 0x70;
static const uint32_t  STATUS_OFF            = 0x60;
static const uint32_t  DELIVERED_MSG_OFF     = 0x98;  // goes non-zero when 0x100 dispatched
static const uintptr_t FN1_RVA               = 0x86BEE0;
static const uintptr_t LOOKUP_RVA            = 0x85FFE0;
static const uintptr_t HANDLER_ENTRY_LOOKUP_RVA = 0x41B7C0;
static const uintptr_t JAM_DISPATCHER_RVA    = 0x41DB60;
static const uintptr_t PARSE_FUNC_1_RVA      = 0x4A0450;
static const uintptr_t PARSE_FUNC_2_RVA      = 0x56CA50;
static const uintptr_t MANAGER_GLOBAL_RVA    = 0x2F53030;
static const uintptr_t TYPE_TAG_GLOBAL_RVA   = 0x2F63214;
static const char*     DUMP_DIR              =
    "CHANGE TO YOUR DESIRED PATH";
static const uintptr_t POISON_KEY            = 0xC6E4F42B57DD7C4DULL;

// ---------------------------------------------------------------------------
static uintptr_t g_base          = 0;
static FILE*     g_log           = nullptr;
static CRITICAL_SECTION g_cs;
static uintptr_t g_cachedSession = 0;
static uintptr_t g_lastKeyWritten= 0;

// ---------------------------------------------------------------------------
static void L(const char* f, ...) {
    char b[1024];
    va_list a; va_start(a, f); _vsnprintf(b, sizeof b, f, a); va_end(a);
    EnterCriticalSection(&g_cs);
    if (g_log) { fprintf(g_log, "[owobs] %s\n", b); fflush(g_log); }
    OutputDebugStringA("[owobs] "); OutputDebugStringA(b); OutputDebugStringA("\n");
    LeaveCriticalSection(&g_cs);
}

static bool readable(void* p, size_t n) {
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQuery(p, &m, sizeof m)) return false;
    if (m.State != MEM_COMMIT) return false;
    DWORD ok = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
               PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    if (m.Protect & PAGE_GUARD) return false;
    if (!(m.Protect & ok)) return false;
    return (uintptr_t)p + n <= (uintptr_t)m.BaseAddress + m.RegionSize;
}
static uint32_t  safe_u32(void* a, uint32_t  d=0) { uint32_t  r; __try{r=*(uint32_t*)a; }__except(EXCEPTION_EXECUTE_HANDLER){return d;} return r; }
static uintptr_t safe_ptr(void* a, uintptr_t d=0) { uintptr_t r; __try{r=*(uintptr_t*)a;}__except(EXCEPTION_EXECUTE_HANDLER){return d;} return r; }

static void refreshManager() {
    void* p = (void*)(g_base + MANAGER_GLOBAL_RVA);
    if (readable(p, 8)) g_managerAddr = safe_ptr(p);
    else g_managerAddr = 0;
}

// ---------------------------------------------------------------------------
static bool validateSession(uintptr_t c) {
    if (!c) return false;
    if (!readable((void*)c, 0x100)) return false;
    if (safe_ptr((void*)c) != g_base + SESSION_VTBL) return false;
    uint32_t st = safe_u32((void*)(c + STATE_OFF), 0xFF);
    return st == 6;
}

static bool isSession(uintptr_t c) {
    if (!readable((void*)c, 0x100)) return false;
    if (safe_ptr((void*)c) != g_base + SESSION_VTBL) return false;
    bool nameOk = false;
    for (uintptr_t o = 0x20; o <= 0x60 && !nameOk; o += 8) {
        __try { if (memcmp((void*)(c+o), "127.0.0.1:3724", 14)==0) nameOk=true; }
        __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (!nameOk) return false;
    return safe_u32((void*)(c + STATE_OFF), 0xFF) == 6;
}

static uintptr_t findSession() {
    uintptr_t vtLo = g_base + VTABLE_WIN_LO, vtHi = g_base + VTABLE_WIN_HI;
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t mx= (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m;
    while (a < mx && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb=(uintptr_t)m.BaseAddress, rs=m.RegionSize;
        if (m.State==MEM_COMMIT && m.Type==MEM_PRIVATE &&
            (m.Protect & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE)) && !(m.Protect & PAGE_GUARD)) {
            for (uintptr_t p=rb; p+8<=rb+rs; p+=8) {
                uintptr_t v; __try{v=*(volatile uintptr_t*)p;}__except(EXCEPTION_EXECUTE_HANDLER){continue;}
                if (v>=vtLo && v<vtHi && isSession(p)) return p;
            }
        }
        a = rb + rs;
    }
    return 0;
}

// ---------------------------------------------------------------------------
static void dumpRegion(uintptr_t rva, size_t before, size_t after) {
    uintptr_t start = g_base + rva - before;
    size_t total = before + after;
    if (!readable((void*)start, total)) { L("dumpRegion: 0x%llX not readable", (unsigned long long)rva); return; }
    CreateDirectoryA(DUMP_DIR, NULL);
    char path[512]; sprintf(path, "%s\\region_%llX.bin", DUMP_DIR, (unsigned long long)rva);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { L("dumpRegion: open %s err %lu", path, GetLastError()); return; }
    DWORD w=0; WriteFile(h, (LPCVOID)start, (DWORD)total, &w, NULL); CloseHandle(h);
    L("dumpRegion: wrote %s", path);
}

static void dumpManagerWindow() {
    if (!g_managerAddr || !readable((void*)g_managerAddr, 0x400)) { L("[mgrdump] not readable"); return; }
    L("[mgrdump] manager=%p +0x100..0x300:", (void*)g_managerAddr);
    for (uintptr_t off=0x100; off<=0x300; off+=16) {
        if (!readable((void*)(g_managerAddr+off), 16)) continue;
        uintptr_t v0=safe_ptr((void*)(g_managerAddr+off+0),0), v1=safe_ptr((void*)(g_managerAddr+off+8),0);
        char t0[32]="", t1[32]="";
        if (v0>=0x0000020000000000ULL && v0<0x00007FFFFFFFFFFFULL) snprintf(t0,sizeof t0," <-HEAP");
        else if (v0<0x100000) snprintf(t0,sizeof t0," <-SMALL:%llu",(unsigned long long)v0);
        if (v1>=0x0000020000000000ULL && v1<0x00007FFFFFFFFFFFULL) snprintf(t1,sizeof t1," <-HEAP");
        else if (v1<0x100000) snprintf(t1,sizeof t1," <-SMALL:%llu",(unsigned long long)v1);
        L("[mgrdump] +0x%03X: %016llX %016llX%s%s", (unsigned int)off, (unsigned long long)v0, (unsigned long long)v1, t0, t1);
    }
}

static void dumpSessionWindow() {
    if (!g_cachedSession || !readable((void*)g_cachedSession, 0x400)) { L("[sessdump] not readable"); return; }
    L("[sessdump] session=%p +0x0..0x400:", (void*)g_cachedSession);
    for (uintptr_t off=0x0; off<=0x400; off+=16) {
        if (!readable((void*)(g_cachedSession+off), 16)) continue;
        uintptr_t v0=safe_ptr((void*)(g_cachedSession+off+0),0), v1=safe_ptr((void*)(g_cachedSession+off+8),0);
        char t0[32]="", t1[32]="";
        if (v0>=0x0000020000000000ULL && v0<0x00007FFFFFFFFFFFULL) snprintf(t0,sizeof t0," <-HEAP");
        else if (v0<0x100000 && v0!=0) snprintf(t0,sizeof t0," <-SMALL:%llu",(unsigned long long)v0);
        if (v1>=0x0000020000000000ULL && v1<0x00007FFFFFFFFFFFULL) snprintf(t1,sizeof t1," <-HEAP");
        else if (v1<0x100000 && v1!=0) snprintf(t1,sizeof t1," <-SMALL:%llu",(unsigned long long)v1);
        if (t0[0] || t1[0])
            L("[sessdump] +0x%03X: %016llX %016llX%s%s", (unsigned int)off, (unsigned long long)v0, (unsigned long long)v1, t0, t1);
    }
}



// ---------------------------- KEY VALIDATION -------------------------------
static bool keyLooksValid(uintptr_t k, const char** why) {
    if (k == 0)                       { *why="zero"; return false; }
    if (k == POISON_KEY)              { *why="poison"; return false; }
    if (k == 0x800000000000000FULL)   { *why="initializer const (0x4A0450)"; return false; }
    if (k == 0xFFFFFFFFFFFFFFFFULL)   { *why="sentinel -1"; return false; }
    if (k == 0x00000000FFFFFFFFULL)   { *why="sentinel u32 -1"; return false; }
    if (k < 0x10000)                  { *why="too small"; return false; }
    if (g_base <= k && k < g_base + 0x4000000) { *why="image pointer"; return false; }
    if (k >= 0x0000010000000000ULL && k < 0x00007FFFFFFFFFFFULL) { *why="heap pointer"; return false; }
    if ((k >> 32) == 0)               { *why="high half zero"; return false; }
    if ((k & 0xFFFFFFFFULL) == 0)     { *why="low half zero"; return false; }
    *why = "ok";
    return true;
}

static bool entryLooksValid(uintptr_t e, const char** why) {
    if (!readable((void*)e, 0x48))    { *why="unreadable"; return false; }
    uintptr_t vt = safe_ptr((void*)e, 0);
    if (!(g_base <= vt && vt < g_base + 0x4000000)) { *why="vtable not in image"; return false; }
    uint32_t flag = safe_u32((void*)(e + 0x28), 0xFF);
    if (flag != 0)                    { *why="flag != 0"; return false; }
    *why = "ok";
    return true;
}

// ---------------------------- STRUCTURAL MAP SCAN --------------------------
static uintptr_t g_foundMap = 0;

static bool inImage(uintptr_t p) { return g_base <= p && p < g_base + 0x4000000; }
static bool inHeap(uintptr_t p)  { return p >= 0x0000010000000000ULL && p < 0x00007FFFFFFFFFFFULL; }

static bool entryChainValid(uintptr_t head, int* outCount, uintptr_t* outKey) {
    int n = 0;
    uintptr_t cur = head, firstKey = 0;
    for (; cur && n < 32; n++) {
        if (!readable((void*)cur, 0x48)) return false;
        uintptr_t vt = safe_ptr((void*)cur, 0);
        if (!inImage(vt)) return false;
        uintptr_t nxt = safe_ptr((void*)(cur + 0x10), 0);
        if (nxt && !inHeap(nxt)) return false;
        uint8_t flag; __try { flag = *(volatile uint8_t*)(cur + 0x28); }
                      __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
        uintptr_t k = safe_ptr((void*)(cur + 0x18), 0);
        if (flag == 0 && k != 0 && !firstKey) firstKey = k;
        if (cur == nxt) break;
        cur = nxt;
    }
    if (n == 0) return false;
    *outCount = n; *outKey = firstKey;
    return true;
}

static uintptr_t scanForMap(uintptr_t* outKey) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t mx = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m;
    int hits = 0;
    while (a < mx && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress, rs = m.RegionSize;
        if (m.State == MEM_COMMIT && m.Type == MEM_PRIVATE &&
            (m.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) && !(m.Protect & PAGE_GUARD) &&
            rs <= 0x8000000) {
            if (!inHeap(rb)) { a = rb + rs; continue; }
            for (uintptr_t p = rb; p + 0x1E0 <= rb + rs; p += 8) {
                uintptr_t head;
                __try { head = *(volatile uintptr_t*)(p + 0x1D8); }
                __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
                if (!head || !inHeap(head)) continue;
                int n = 0; uintptr_t k = 0;
                if (!entryChainValid(head, &n, &k)) continue;
                if (!k) continue;
                const char* kw;
                if (!keyLooksValid(k, &kw)) continue;
                uintptr_t evt = safe_ptr((void*)head, 0);
                uint32_t  e40 = safe_u32((void*)(head + 0x40), 0xFFFFFFFF);
                L("[map] CANDIDATE map=%p head=%p entries=%d key=%016llX vtblRVA=0x%llX +0x40=%u",
                  (void*)p, (void*)head, n, (unsigned long long)k,
                  (unsigned long long)(evt - g_base), e40);
                if (++hits >= 8) { *outKey = k; return p; }
                *outKey = k;
                g_foundMap = p;
            }
        }
        a = rb + rs;
    }
    return g_foundMap;
}



// ---------------------------- CONNECTION SCAN ------------------------------
static uintptr_t g_conn = 0;
static uintptr_t g_watchEntry = 0;
static void writePendingKeyToFile(uintptr_t key);

static void dumpAround(uintptr_t obj, uintptr_t lo, uintptr_t hi, const char* tag) {
    for (uintptr_t off = lo; off <= hi; off += 16) {
        if (!readable((void*)(obj + off), 16)) continue;
        uintptr_t v0 = safe_ptr((void*)(obj + off), 0);
        uintptr_t v1 = safe_ptr((void*)(obj + off + 8), 0);
        char t0[40] = "", t1[40] = "";
        if (inImage(v0)) snprintf(t0, sizeof t0, " <-IMG:0x%llX", (unsigned long long)(v0 - g_base));
        else if (inHeap(v0)) snprintf(t0, sizeof t0, " <-HEAP");
        if (inImage(v1)) snprintf(t1, sizeof t1, " <-IMG:0x%llX", (unsigned long long)(v1 - g_base));
        else if (inHeap(v1)) snprintf(t1, sizeof t1, " <-HEAP");
        L("[%s] +0x%03X: %016llX %016llX%s%s", tag, (unsigned int)off,
          (unsigned long long)v0, (unsigned long long)v1, t0, t1);
    }
}

static void probeConnMap(uintptr_t conn) {
    uintptr_t map = conn - 8;
    uintptr_t head = safe_ptr((void*)(map + 0x1D8), 0);
    L("[conn] conn=%p  map(conn-8)=%p  [map+0x1D8]=%p",
      (void*)conn, (void*)map, (void*)head);
    if (!head || !inHeap(head) || !readable((void*)head, 0x48)) {
        L("[conn]   head not a walkable heap object");
        return;
    }
    uintptr_t cur = head;
    for (int i = 0; i < 16 && cur; i++) {
        if (!readable((void*)cur, 0x100)) break;
        uintptr_t vt = safe_ptr((void*)cur, 0);
        uintptr_t k  = safe_ptr((void*)(cur + 0x18), 0);
        uintptr_t nx = safe_ptr((void*)(cur + 0x10), 0);
        uint8_t fl = 0xFF; __try { fl = *(volatile uint8_t*)(cur + 0x28); }
                           __except(EXCEPTION_EXECUTE_HANDLER) {}
        uint32_t s40 = safe_u32((void*)(cur + 0x40), 0xFFFFFFFF);
        L("[conn]   entry#%d=%p vtblRVA=0x%llX flag=%u key=%016llX +0x40=%u",
          i, (void*)cur, (unsigned long long)(vt - g_base), fl,
          (unsigned long long)k, s40);
        if (fl == 0 && k) {
            const char* kw;
            if (keyLooksValid(k, &kw)) {
                g_watchEntry = cur;
                L("[conn]   *** PENDING ENTRY key=%016llX ***", (unsigned long long)k);
                writePendingKeyToFile(k);
            } else {
                L("[conn]   key rejected: %s", kw);
            }
        }
        if (nx == cur) break;
        cur = nx;
    }
}

static void scanForConn() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t mx = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m;
    int found = 0;
    while (a < mx && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress, rs = m.RegionSize;
        if (m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && inHeap(rb) &&
            (m.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) && !(m.Protect & PAGE_GUARD) &&
            rs <= 0x8000000) {
            for (uintptr_t p = rb; p + 0x260 <= rb + rs; p += 8) {
                uint32_t st;
                __try { st = *(volatile uint32_t*)(p + 0x20); }
                __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
                if (st != 6) continue;
                uintptr_t lh;
                __try { lh = *(volatile uintptr_t*)(p + 0x250); }
                __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
                if (lh != p + 0x250 && !inHeap(lh)) continue;
                uint32_t f10 = safe_u32((void*)(p + 0x10), 0xFFFFFFFF);
                if (f10 > 4) continue;
                L("[conn] CANDIDATE conn=%p [+0x10]=%u [+0x250]=%p %s",
                  (void*)p, f10, (void*)lh, (lh == p + 0x250) ? "(empty list)" : "(has nodes)");
                g_conn = p;
                probeConnMap(p);
                if (++found == 1) dumpAround(p, 0x1C0, 0x260, "conndump");
                if (found >= 6) return;
            }
        }
        a = rb + rs;
    }
    if (!found) L("[conn] no connection object matched the dispatcher fingerprint");
}


// ---------------------------- DUAL-VTABLE MANAGER SCAN ---------------------
static bool tightHeap(uintptr_t p) {
    return p >= 0x0000010000000000ULL && p < 0x00007FF000000000ULL && (p & 7) == 0;
}

static void scanForManager() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t mx = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m;
    int found = 0;
    while (a < mx && VirtualQuery((void*)a, &m, sizeof m)) {
        uintptr_t rb = (uintptr_t)m.BaseAddress, rs = m.RegionSize;
        if (m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && tightHeap(rb) &&
            (m.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) && !(m.Protect & PAGE_GUARD) &&
            rs <= 0x8000000) {
            for (uintptr_t p = rb; p + 0x1E0 <= rb + rs; p += 8) {
                uintptr_t vt0, vt1, head;
                __try {
                    vt0  = *(volatile uintptr_t*)(p + 0x00);
                    vt1  = *(volatile uintptr_t*)(p + 0x08);
                    head = *(volatile uintptr_t*)(p + 0x1D8);
                } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }

                if (!inImage(vt0) || !inImage(vt1) || vt0 == vt1) continue;
                if (!head || !tightHeap(head)) continue;
                if (!readable((void*)head, 0x100)) continue;

                uintptr_t evt = safe_ptr((void*)head, 0);
                if (!inImage(evt)) continue;
                uint8_t fl = 0xFF;
                __try { fl = *(volatile uint8_t*)(head + 0x28); }
                __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
                uintptr_t k   = safe_ptr((void*)(head + 0x18), 0);
                uintptr_t nx  = safe_ptr((void*)(head + 0x10), 0);
                uint32_t  s40 = safe_u32((void*)(head + 0x40), 0xFFFFFFFF);

                L("[mgr] M=%p vt0RVA=0x%llX vt1RVA=0x%llX head=%p entryVtblRVA=0x%llX "
                  "flag=%u key=%016llX next=%p +0x40=%u",
                  (void*)p, (unsigned long long)(vt0 - g_base), (unsigned long long)(vt1 - g_base),
                  (void*)head, (unsigned long long)(evt - g_base), fl,
                  (unsigned long long)k, (void*)nx, s40);

                if (fl == 0 && k) {
                    const char* kw;
                    if (keyLooksValid(k, &kw)) {
                        g_watchEntry = head;
                        L("[mgr]   *** PENDING ENTRY M=%p key=%016llX ***",
                          (void*)p, (unsigned long long)k);
                        writePendingKeyToFile(k);
                    } else {
                        L("[mgr]   key rejected: %s", kw);
                    }
                }
                if (++found >= 12) return;
            }
        }
        a = rb + rs;
    }
    if (!found) L("[mgr] no dual-vtable object with a list at +0x1D8 found");
}

// ---------------------------- ACCEPT ORACLE --------------------------------
static void watchAcceptFlag() {
    if (!g_watchEntry || !readable((void*)g_watchEntry, 0x48)) return;
    uint32_t v = safe_u32((void*)(g_watchEntry + 0x40), 0xFFFFFFFF);
    if (v == 4) {
        uint32_t f0 = safe_u32((void*)(g_watchEntry + 0xF0), 0);
        uint32_t f4 = safe_u32((void*)(g_watchEntry + 0xF4), 0);
        L("*** ACCEPTED *** entry=%p +0x40=4  +0xF0=%08X +0xF4=%08X",
          (void*)g_watchEntry, f0, f4);
    }
}

// ---------------------------- KEY DISCOVERY --------------------------------
static uintptr_t discoverPendingKey() {
    scanForManager();
    if (g_lastKeyWritten) return g_lastKeyWritten;
    {
        uintptr_t k = 0;
        uintptr_t mp = scanForMap(&k);
        if (mp && k) {
            g_watchEntry = safe_ptr((void*)(mp + 0x1D8), 0);
            L("[key] USING structural map=%p entry=%p key=%016llX",
              (void*)mp, (void*)g_watchEntry, (unsigned long long)k);
            return k;
        }
    }
    refreshManager();
    // Source 1: manager list at known offsets
    if (g_managerAddr) {
        const uintptr_t offs[] = {0x1E0, 0x180, 0x100, 0x1D8};
        for (int oi=0; oi<4; oi++) {
            uintptr_t entry = safe_ptr((void*)(g_managerAddr+offs[oi]), 0);
            for (int i=0; i<32 && entry; i++) {
                if (!readable((void*)entry, 0x30)) break;
                uintptr_t k   = safe_ptr((void*)(entry+0x18), 0);
                uint32_t  flag= safe_u32 ((void*)(entry+0x28), 0xFF);
                const char* ew; const char* kw;
                if (entryLooksValid(entry, &ew) && keyLooksValid(k, &kw)) {
                    L("[key] ACCEPT manager+0x%X entry=%p key=%016llX",
                      (unsigned int)offs[oi], (void*)entry, (unsigned long long)k);
                    return k;
                }
                if (k != 0 && k != POISON_KEY)
                    L("[key] reject manager+0x%X entry=%p key=%016llX (entry:%s key:%s)",
                      (unsigned int)offs[oi], (void*)entry, (unsigned long long)k, ew, kw);
                (void)flag;
                entry = safe_ptr((void*)(entry+0x10), 0);
            }
        }
    }
    // Source 2: session-relative map (session+0x270 found 8C48EB734137BF12 consistently)
    if (g_cachedSession && readable((void*)g_cachedSession, 0x400)) {
        const uintptr_t soffs[] = {0x270, 0x2D0, 0x1D8, 0x1E0};
        for (int oi=0; oi<4; oi++) {
            uintptr_t head = safe_ptr((void*)(g_cachedSession+soffs[oi]), 0);
            for (int i=0; i<16 && head; i++) {
                if (!readable((void*)head, 0x30)) break;
                uintptr_t k   = safe_ptr((void*)(head+0x18), 0);
                uint32_t  flag= safe_u32 ((void*)(head+0x28), 0xFF);
                const char* ew; const char* kw;
                if (entryLooksValid(head, &ew) && keyLooksValid(k, &kw)) {
                    L("[key] ACCEPT session+0x%X entry=%p key=%016llX",
                      (unsigned int)soffs[oi], (void*)head, (unsigned long long)k);
                    return k;
                }
                if (k != 0 && k != POISON_KEY)
                    L("[key] reject session+0x%X entry=%p key=%016llX (entry:%s key:%s)",
                      (unsigned int)soffs[oi], (void*)head, (unsigned long long)k, ew, kw);
                (void)flag;
                head = safe_ptr((void*)(head+0x10), 0);
            }
        }
    }
    return 0;
}

static void writePendingKeyToFile(uintptr_t key) {
    if (!key || key==POISON_KEY || key==g_lastKeyWritten) return;
    FILE* f = fopen(PENDING_KEY_FILE, "w");
    if (!f) { L("[key] open FAILED"); return; }
    fprintf(f, "%016llX", (unsigned long long)key);
    fclose(f);
    g_lastKeyWritten = key;
    L("[key] wrote %016llX", (unsigned long long)key);
}

// ---------------------------------------------------------------------------
static DWORD WINAPI worker(LPVOID) {
    InitializeCriticalSection(&g_cs);
    g_log = fopen(LOG_PATH, "a");
    g_base = (uintptr_t)GetModuleHandleW(L"Overwatch.exe");
    if (!g_base) g_base = (uintptr_t)GetModuleHandleW(NULL);
    L("v4.7 base=%p dual-vtable manager scan (vt@+0, vt@+8, list@+0x1D8)", (void*)g_base);

    Sleep(g_startDelayMs);
    refreshManager();
    L("manager=%p", (void*)g_managerAddr);

    if (g_dumpCode) {
        L("Dumping regions...");
        dumpRegion(FN1_RVA,               0x20, 0x300);
        dumpRegion(LOOKUP_RVA,            0x20, 0x200);
        dumpRegion(HANDLER_ENTRY_LOOKUP_RVA,0x20,0x200);
        dumpRegion(JAM_DISPATCHER_RVA,    0x20, 0x600);
        dumpRegion(PARSE_FUNC_1_RVA,      0x20, 0x200);
        dumpRegion(PARSE_FUNC_2_RVA,      0x20, 0x200);
    }

    L("Main loop starting.");
    bool dumpedOnce = false;
    uint32_t missStreak = 0;

    for (;;) {
        // --- Session validation ---
        if (!validateSession(g_cachedSession))
            g_cachedSession = findSession();

        if (!validateSession(g_cachedSession)) {
            ++missStreak;
            if (missStreak == 5) { dumpedOnce = false; g_lastKeyWritten = 0; }
            Sleep(missStreak <= 4 ? 300 : 2000);
            continue;
        }
        missStreak = 0;

        if (!dumpedOnce) {
            dumpedOnce = true;
            refreshManager();
            dumpManagerWindow();
            dumpSessionWindow();
        }

        // --- Check session+0x98 for the connect-frame trigger ---
        uintptr_t delivered = safe_ptr((void*)(g_cachedSession + DELIVERED_MSG_OFF), 0);
        uint32_t  state     = safe_u32 ((void*)(g_cachedSession + STATE_OFF), 0xFF);
        uint32_t  status    = safe_u32 ((void*)(g_cachedSession + STATUS_OFF), 0xFF);
        L("[poll] session=%p state=%u status=%u +0x98=%p",
          (void*)g_cachedSession, state, status, (void*)delivered);

        if (delivered != 0 && state == 6) {
            // 0x100 frame has been dispatched — switch to fast-poll and
            // hammer the key lookup until we find it or the window closes.
            L("[FAST] +0x98 fired (%p) — entering fast-poll (20ms x %u)",
              (void*)delivered, g_fastPollBudget);
            uint32_t budget = g_fastPollBudget;
            while (budget--) {
                if (!validateSession(g_cachedSession)) break;
                uint32_t st2 = safe_u32((void*)(g_cachedSession + STATUS_OFF), 0xFF);
                if (st2 != 6 && st2 != 0) {
                    // verdict already fired (2=reject, 7=accept)
                    L("[FAST] verdict=%u at budget=%u — fast-poll done", st2, budget);
                    break;
                }
                watchAcceptFlag();
                uintptr_t key = discoverPendingKey();
                if (key) {
                    writePendingKeyToFile(key);
                    // Keep fast-polling until verdict — accept the first find but
                    // also log subsequent finds in case key rotates
                }
                Sleep(g_fastPollMs);
            }
            L("[FAST] fast-poll complete");
            // Reset for next park
            g_lastKeyWritten = 0;
            Sleep(g_normalPollMs);
        } else {
            // No trigger yet — try key discovery anyway (belt-and-suspenders)
            uintptr_t key = discoverPendingKey();
            if (key) writePendingKeyToFile(key);
            Sleep(g_normalPollMs);
        }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        InitializeCriticalSection(&g_cs);
        HANDLE handle = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (handle) CloseHandle(handle);
    }
    return TRUE;
}
