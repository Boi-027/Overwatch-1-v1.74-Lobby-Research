// owobs_v69.cpp - Call Success() directly instead of just writing status=7.
// Writing 7 prevented the timeout but didn't advance the lobby because it
// skipped Success()'s callbacks and state initialization. This build calls
// the actual function at RVA 0xE38600 with the session object as 'this' (rcx).
// RISK: the function may be Arxan-encrypted at rest (calling it = executing
// garbage → crash), or it may expect specific thread/stack context. If it
// crashes, that tells us the function is protected or has requirements.
// If it WORKS, it properly advances the lobby — the real breakthrough.

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>

static const char* LOG_PATH="owobs_log.txt";
static const uint32_t START_DELAY_MS=8000;
static uintptr_t g_base=0; static FILE* g_log=nullptr;
static const uintptr_t SESSION_VTBL=0x2616260;
static const uintptr_t SUCCESS_RVA=0xE38600;

static void L(const char*f,...){char b[1024];va_list a;va_start(a,f);_vsnprintf(b,sizeof b,f,a);va_end(a);
    if(g_log){fprintf(g_log,"[owobs] %s\n",b);fflush(g_log);} OutputDebugStringA("[owobs] ");OutputDebugStringA(b);OutputDebugStringA("\n");}
static uint32_t u32(void*a,uint32_t d=0xEEEE){uint32_t r;__try{r=*(uint32_t*)a;}__except(1){return d;}return r;}

static uintptr_t findSession(){
    uintptr_t want=g_base+SESSION_VTBL;
    SYSTEM_INFO si;GetSystemInfo(&si);
    uintptr_t a=(uintptr_t)si.lpMinimumApplicationAddress,mx=(uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m;
    while(a<mx&&VirtualQuery((void*)a,&m,sizeof m)){
        uintptr_t rb=(uintptr_t)m.BaseAddress,rs=m.RegionSize;
        if(m.State==MEM_COMMIT&&m.Type==MEM_PRIVATE&&
           rb>=0x10000000000ULL&&rb<0x7FF000000000ULL&&rs<=0x8000000&&
           (m.Protect&(PAGE_READWRITE|PAGE_EXECUTE_READWRITE))&&!(m.Protect&PAGE_GUARD)){
            __try{ for(uintptr_t p=rb;p+8<=rb+rs;p+=8){
                if(*(uintptr_t*)p==want) return p; } }__except(1){}
        }
        a=rb+rs;
    }
    return 0;
}
static double now_ms(){LARGE_INTEGER f,c;QueryPerformanceFrequency(&f);QueryPerformanceCounter(&c);
    return 1000.0*(double)c.QuadPart/(double)f.QuadPart;}

// Success() prototype: void __fastcall Success(void* this)
// x64: rcx = this
typedef void (__fastcall *SuccessFn)(void*);

static DWORD WINAPI worker(LPVOID){
    g_log=fopen(LOG_PATH,"a");
    g_base=(uintptr_t)GetModuleHandleW(L"Overwatch.exe"); if(!g_base)g_base=(uintptr_t)GetModuleHandleW(NULL);
    SuccessFn pSuccess = (SuccessFn)(g_base + SUCCESS_RVA);
    L("v69 CALL Success() directly. base=%p Success=%p",(void*)g_base,(void*)pSuccess);
    Sleep(START_DELAY_MS);
    
    uintptr_t sess=0; int gen=0; double t0=now_ms();
    uint32_t lastS=0xEEEE,lastT=0xEEEE;
    bool called=false;
    for(;;){
        if(!sess){
            uintptr_t f=findSession();
            if(f){ sess=f; gen++; lastS=lastT=0xEEEE; called=false;
                L("[v] === session gen#%d @ %p (t=%.1fms) ===",gen,(void*)sess,now_ms()-t0);
            } else { Sleep(1); continue; }
        }
        uintptr_t chk=0; __try{chk=*(uintptr_t*)sess;}__except(1){chk=0;}
        if(chk!=g_base+SESSION_VTBL){ L("[v] session gen#%d gone (t=%.1fms)",gen,now_ms()-t0); sess=0; continue; }
        
        uint32_t st=u32((void*)(sess+0x60)),stt=u32((void*)(sess+0x70));
        if(st!=lastS||stt!=lastT){
            const char*v=st==2?" REJECT":st==7?" ACCEPT":st==6?" (awaiting)":"";
            L("[v] t=%.1fms status=%u state=%u%s",now_ms()-t0,st,stt,v);
            lastS=st;lastT=stt;
        }
        // When status reaches 6, wait a moment then CALL Success()
        if(st==6 && stt==6 && !called){
            Sleep(100);
            uint32_t confirm=u32((void*)(sess+0x60));
            if(confirm==6){
                L("[v] >>> CALLING Success(%p) at t=%.1fms <<<",(void*)sess,now_ms()-t0);
                // check the first bytes at the function to see if they look like code
                uint8_t* fn=(uint8_t*)pSuccess;
                uint8_t first4[4]; __try{first4[0]=fn[0];first4[1]=fn[1];first4[2]=fn[2];first4[3]=fn[3];}
                __except(1){first4[0]=first4[1]=first4[2]=first4[3]=0xCC;}
                L("[v]   Success first bytes: %02x %02x %02x %02x",first4[0],first4[1],first4[2],first4[3]);
                __try{
                    pSuccess((void*)sess);
                    L("[v] >>> Success() RETURNED OK! <<<");
                }__except(1){
                    L("[v] >>> Success() CRASHED (exception) <<<");
                }
                called=true;
                uint32_t after=u32((void*)(sess+0x60));
                L("[v] status after Success(): %u",after);
                // watch for 15s
                double ft=now_ms(); uint32_t ps=after,pt=stt;
                while(now_ms()-ft<15000.0){
                    uint32_t s2=u32((void*)(sess+0x60)),t2=u32((void*)(sess+0x70));
                    if(s2!=ps||t2!=pt){
                        L("[v] t=%.1fms status=%u state=%u (post-Success)",now_ms()-t0,s2,t2);
                        ps=s2;pt=t2;
                    }
                }
                L("[v] 15s post-Success watch done");
            }
        }
    }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID){
    if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);
        HANDLE t=CreateThread(nullptr,0,worker,nullptr,0,nullptr); if(t)CloseHandle(t);}
    return TRUE;
}
