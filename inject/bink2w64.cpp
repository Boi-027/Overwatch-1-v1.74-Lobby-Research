// bink2w64.cpp � BinkyProxy (loader-only) v2
// Fixes vs v1: duplicate BinkSetWillLoop export removed; no FreeLibrary in
// DETACH; file logging added; _CRT_SECURE_NO_WARNINGS defined so the fopen
// in Log() compiles clean under the VS IDE (C4996) as well as the CLI.
//
// Build (MSVC x64 dev prompt):
//   cl /nologo /LD /O2 /D_CRT_SECURE_NO_WARNINGS /Fe:bink2w64.dll dllmain.cpp
// Output bink2w64.dll goes next to Overwatch.exe (real DLL stays as
// bink2w64_original.dll).

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

static HMODULE g_hOriginalDll = NULL;

static void LoadOriginalBink() {
    if (!g_hOriginalDll)
        g_hOriginalDll = LoadLibraryA("bink2w64_original.dll");
}

static void Log(const char* s) {
    OutputDebugStringA(s);
    FILE* f = nullptr;
    if (fopen_s(&f, "CHANGE TO YOUR DESIRED PATH", "a") == 0 && f) {
        fprintf(f, "[%llu] %s", (unsigned long long)GetTickCount64(), s);
        fclose(f);
    }
}

// --- export forwarders (NAME -> bink2w64_original.NAME) ---
#pragma comment(linker, "/export:BinkAllocateFrameBuffers=bink2w64_original.BinkAllocateFrameBuffers")
#pragma comment(linker, "/export:BinkClose=bink2w64_original.BinkClose")
#pragma comment(linker, "/export:BinkCloseTrack=bink2w64_original.BinkCloseTrack")
#pragma comment(linker, "/export:BinkControlBackgroundIO=bink2w64_original.BinkControlBackgroundIO")
#pragma comment(linker, "/export:BinkCopyToBuffer=bink2w64_original.BinkCopyToBuffer")
#pragma comment(linker, "/export:BinkCopyToBufferRect=bink2w64_original.BinkCopyToBufferRect")
#pragma comment(linker, "/export:BinkDoFrame=bink2w64_original.BinkDoFrame")
#pragma comment(linker, "/export:BinkDoFrameAsync=bink2w64_original.BinkDoFrameAsync")
#pragma comment(linker, "/export:BinkDoFrameAsyncMulti=bink2w64_original.BinkDoFrameAsyncMulti")
#pragma comment(linker, "/export:BinkDoFrameAsyncWait=bink2w64_original.BinkDoFrameAsyncWait")
#pragma comment(linker, "/export:BinkDoFramePlane=bink2w64_original.BinkDoFramePlane")
#pragma comment(linker, "/export:BinkFreeGlobals=bink2w64_original.BinkFreeGlobals")
#pragma comment(linker, "/export:BinkGetError=bink2w64_original.BinkGetError")
#pragma comment(linker, "/export:BinkGetFrameBuffersInfo=bink2w64_original.BinkGetFrameBuffersInfo")
#pragma comment(linker, "/export:BinkGetGPUDataBuffersInfo=bink2w64_original.BinkGetGPUDataBuffersInfo")
#pragma comment(linker, "/export:BinkGetKeyFrame=bink2w64_original.BinkGetKeyFrame")
#pragma comment(linker, "/export:BinkGetPlatformInfo=bink2w64_original.BinkGetPlatformInfo")
#pragma comment(linker, "/export:BinkGetRealtime=bink2w64_original.BinkGetRealtime")
#pragma comment(linker, "/export:BinkGetRects=bink2w64_original.BinkGetRects")
#pragma comment(linker, "/export:BinkGetSummary=bink2w64_original.BinkGetSummary")
#pragma comment(linker, "/export:BinkGetTrackData=bink2w64_original.BinkGetTrackData")
#pragma comment(linker, "/export:BinkGetTrackID=bink2w64_original.BinkGetTrackID")
#pragma comment(linker, "/export:BinkGetTrackMaxSize=bink2w64_original.BinkGetTrackMaxSize")
#pragma comment(linker, "/export:BinkGetTrackType=bink2w64_original.BinkGetTrackType")
#pragma comment(linker, "/export:BinkGoto=bink2w64_original.BinkGoto")
#pragma comment(linker, "/export:BinkLogoAddress=bink2w64_original.BinkLogoAddress")
#pragma comment(linker, "/export:BinkNextFrame=bink2w64_original.BinkNextFrame")
#pragma comment(linker, "/export:BinkOpen=bink2w64_original.BinkOpen")
#pragma comment(linker, "/export:BinkOpenDirectSound=bink2w64_original.BinkOpenDirectSound")
#pragma comment(linker, "/export:BinkOpenMiles=bink2w64_original.BinkOpenMiles")
#pragma comment(linker, "/export:BinkOpenTrack=bink2w64_original.BinkOpenTrack")
#pragma comment(linker, "/export:BinkOpenWaveOut=bink2w64_original.BinkOpenWaveOut")
#pragma comment(linker, "/export:BinkOpenWithOptions=bink2w64_original.BinkOpenWithOptions")
#pragma comment(linker, "/export:BinkOpenXAudio2=bink2w64_original.BinkOpenXAudio2")
#pragma comment(linker, "/export:BinkOpenXAudio27=bink2w64_original.BinkOpenXAudio27")
#pragma comment(linker, "/export:BinkOpenXAudio28=bink2w64_original.BinkOpenXAudio28")
#pragma comment(linker, "/export:BinkPause=bink2w64_original.BinkPause")
#pragma comment(linker, "/export:BinkRegisterFrameBuffers=bink2w64_original.BinkRegisterFrameBuffers")
#pragma comment(linker, "/export:BinkRegisterGPUDataBuffers=bink2w64_original.BinkRegisterGPUDataBuffers")
#pragma comment(linker, "/export:BinkRequestStopAsyncThread=bink2w64_original.BinkRequestStopAsyncThread")
#pragma comment(linker, "/export:BinkRequestStopAsyncThreadsMulti=bink2w64_original.BinkRequestStopAsyncThreadsMulti")
#pragma comment(linker, "/export:BinkService=bink2w64_original.BinkService")
#pragma comment(linker, "/export:BinkSetError=bink2w64_original.BinkSetError")
#pragma comment(linker, "/export:BinkSetFileOffset=bink2w64_original.BinkSetFileOffset")
#pragma comment(linker, "/export:BinkSetFrameRate=bink2w64_original.BinkSetFrameRate")
#pragma comment(linker, "/export:BinkSetIO=bink2w64_original.BinkSetIO")
#pragma comment(linker, "/export:BinkSetIOSize=bink2w64_original.BinkSetIOSize")
#pragma comment(linker, "/export:BinkSetMemory=bink2w64_original.BinkSetMemory")
#pragma comment(linker, "/export:BinkSetOSFileCallbacks=bink2w64_original.BinkSetOSFileCallbacks")
#pragma comment(linker, "/export:BinkSetPan=bink2w64_original.BinkSetPan")
#pragma comment(linker, "/export:BinkSetSimulate=bink2w64_original.BinkSetSimulate")
#pragma comment(linker, "/export:BinkSetSoundOnOff=bink2w64_original.BinkSetSoundOnOff")
#pragma comment(linker, "/export:BinkSetSoundSystem=bink2w64_original.BinkSetSoundSystem")
#pragma comment(linker, "/export:BinkSetSoundSystem2=bink2w64_original.BinkSetSoundSystem2")
#pragma comment(linker, "/export:BinkSetSoundTrack=bink2w64_original.BinkSetSoundTrack")
#pragma comment(linker, "/export:BinkSetSpeakerVolumes=bink2w64_original.BinkSetSpeakerVolumes")
#pragma comment(linker, "/export:BinkSetVideoOnOff=bink2w64_original.BinkSetVideoOnOff")
#pragma comment(linker, "/export:BinkSetVolume=bink2w64_original.BinkSetVolume")
#pragma comment(linker, "/export:BinkSetWillLoop=bink2w64_original.BinkSetWillLoop")
#pragma comment(linker, "/export:BinkShouldSkip=bink2w64_original.BinkShouldSkip")
#pragma comment(linker, "/export:BinkStartAsyncThread=bink2w64_original.BinkStartAsyncThread")
#pragma comment(linker, "/export:BinkUtilCPUs=bink2w64_original.BinkUtilCPUs")
#pragma comment(linker, "/export:BinkUtilFree=bink2w64_original.BinkUtilFree")
#pragma comment(linker, "/export:BinkUtilMalloc=bink2w64_original.BinkUtilMalloc")
#pragma comment(linker, "/export:BinkUtilMutexCreate=bink2w64_original.BinkUtilMutexCreate")
#pragma comment(linker, "/export:BinkUtilMutexDestroy=bink2w64_original.BinkUtilMutexDestroy")
#pragma comment(linker, "/export:BinkUtilMutexLock=bink2w64_original.BinkUtilMutexLock")
#pragma comment(linker, "/export:BinkUtilMutexLockTimeOut=bink2w64_original.BinkUtilMutexLockTimeOut")
#pragma comment(linker, "/export:BinkUtilMutexUnlock=bink2w64_original.BinkUtilMutexUnlock")
#pragma comment(linker, "/export:BinkWait=bink2w64_original.BinkWait")
#pragma comment(linker, "/export:BinkWaitStopAsyncThread=bink2w64_original.BinkWaitStopAsyncThread")
#pragma comment(linker, "/export:BinkWaitStopAsyncThreadsMulti=bink2w64_original.BinkWaitStopAsyncThreadsMulti")
#pragma comment(linker, "/export:RADTimerRead=bink2w64_original.RADTimerRead")

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(h);
        LoadOriginalBink();
        Log("[binky] proxy loaded (v2 loader-only)\n");
        LoadLibraryA("cainj.dll");
        LoadLibraryA("owobs.dll");
        // LoadLibraryA("hook_probe.dll");
        // LoadLibraryA("protect_sweep.dll");
        break;
    case DLL_PROCESS_DETACH:
        // intentionally empty: never FreeLibrary the real Bink from DllMain
        break;
    }
    return TRUE;
}