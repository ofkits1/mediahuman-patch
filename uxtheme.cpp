#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#include "uxtheme_slot_names.inc"

extern "C" void *g_slots[UX_THEME_EXPORT_COUNT];
extern "C" void UxThemeStub(void);

#define TARGET L"YouTubeDownloader.exe"

static const BYTE jmp_short = 0xEB;
static const BYTE patch_reg_get[] = { 0xB0, 0x01, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90 };
static const BYTE patch_ecx1[] = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90 };
static const BYTE patch_edx1[] = { 0xBA, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 };

typedef struct {
    const char *sig;
    DWORD off;
    const BYTE *val;
    SIZE_T len;
} patch_rule;

typedef struct {
    const char *sig;
    const patch_rule *parts;
    SIZE_T n;
} patch_group;

static const char sig_trial[] = "83 F8 14 ?? 31 48 83 7B 18 00 ??";

static const patch_rule trial_parts[] = {
    { sig_trial, 3, &jmp_short, 1 },
    { sig_trial, 10, &jmp_short, 1 },
};

static const patch_rule single_rules[] = {
    { "0F B6 81 F0 01 00 00 C3", 0, patch_reg_get, 8 },
    { "0F B6 97 F0 01 00 00", 0, patch_edx1, 7 },
    { "0F B6 91 F0 01 00 00", 0, patch_edx1, 7 },
    { "8B 8D 08 04 00 00 85 C9 74 10 83 E9 01 74 6D", 0, patch_ecx1, 6 },
};

static int hex_nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static SIZE_T parse_sig(const char *hex, BYTE *pat, BYTE *mask, SIZE_T cap)
{
    SIZE_T n = 0;
    const char *p = hex;

    while (*p && n < cap) {
        while (*p == ' ') p++;
        if (!p[0] || !p[1]) break;
        if (p[0] == '?' || p[1] == '?') {
            pat[n] = 0;
            mask[n] = 0;
            n++;
            p += 2;
            while (*p == ' ') p++;
            continue;
        }
        int hi = hex_nib(p[0]);
        int lo = hex_nib(p[1]);
        if (hi < 0 || lo < 0) return 0;
        pat[n] = (BYTE)((hi << 4) | lo);
        mask[n] = 0xFF;
        n++;
        p += 2;
    }
    return n;
}

static BYTE *find_sig(const BYTE *base, SIZE_T size, const char *hex, SIZE_T start)
{
    BYTE pat[32], mask[32];
    SIZE_T n = parse_sig(hex, pat, mask, sizeof(pat));
    SIZE_T i, j;

    if (!n || n > size || start >= size) return NULL;

    for (i = start; i + n <= size; i++) {
        for (j = 0; j < n; j++) {
            if (mask[j] && base[i + j] != pat[j]) break;
        }
        if (j == n) return (BYTE *)(base + i);
    }
    return NULL;
}

static BOOL write_mem(BYTE *addr, const BYTE *val, SIZE_T len)
{
    DWORD old;

    if (!len) return TRUE;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    for (SIZE_T i = 0; i < len; i++) addr[i] = val[i];
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return TRUE;
}

static BOOL apply_rule(BYTE *hit, const patch_rule *r)
{
    return write_mem(hit + r->off, r->val, r->len);
}

static BOOL apply_rules(const BYTE *img, SIZE_T sz, const patch_rule *r)
{
    SIZE_T start = 0;
    BYTE *hit;
    BOOL ok = FALSE;

    while ((hit = find_sig(img, sz, r->sig, start)) != NULL) {
        if (apply_rule(hit, r)) ok = TRUE;
        start = (SIZE_T)(hit - img) + 1;
    }
    return ok;
}

static BOOL apply_group(const BYTE *img, SIZE_T sz, const patch_group *g)
{
    SIZE_T start = 0;
    BYTE *hit;
    BOOL ok = FALSE;
    SIZE_T i;

    while ((hit = find_sig(img, sz, g->sig, start)) != NULL) {
        for (i = 0; i < g->n; i++) {
            if (apply_rule(hit, &g->parts[i])) ok = TRUE;
        }
        start = (SIZE_T)(hit - img) + 1;
    }
    return ok;
}

static BOOL patch_sigs(BYTE *base, SIZE_T sz)
{
    BOOL ok = FALSE;
    patch_group trial = { sig_trial, trial_parts, sizeof(trial_parts) / sizeof(trial_parts[0]) };
    SIZE_T i;

    if (apply_group(base, sz, &trial)) ok = TRUE;
    for (i = 0; i < sizeof(single_rules) / sizeof(single_rules[0]); i++) {
        if (apply_rules(base, sz, &single_rules[i])) ok = TRUE;
    }
    return ok;
}

static BOOL patch_rva(BYTE *base)
{
    BOOL ok = FALSE;

    if (write_mem(base + 0x002A0E4F, &jmp_short, 1)) ok = TRUE;
    if (write_mem(base + 0x002A0E48, &jmp_short, 1)) ok = TRUE;
    if (write_mem(base + 0x00313A50, patch_reg_get, 8)) ok = TRUE;
    if (write_mem(base + 0x00311F68, patch_edx1, 7)) ok = TRUE;
    if (write_mem(base + 0x003122F1, patch_edx1, 7)) ok = TRUE;
    if (write_mem(base + 0x003124F3, patch_edx1, 7)) ok = TRUE;
    if (write_mem(base + 0x00315530, patch_edx1, 7)) ok = TRUE;
    if (write_mem(base + 0x00311ACF, patch_ecx1, 6)) ok = TRUE;
    if (write_mem(base + 0x0029731F, &jmp_short, 1)) ok = TRUE;
    if (write_mem(base + 0x00297318, &jmp_short, 1)) ok = TRUE;
    return ok;
}

static BOOL do_patch(void)
{
    HMODULE mod;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    SIZE_T sz;
    BOOL ok = FALSE;

    mod = GetModuleHandleW(TARGET);
    if (!mod) return FALSE;

    dos = (PIMAGE_DOS_HEADER)mod;
    nt = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    sz = nt->OptionalHeader.SizeOfImage;

    if (patch_sigs((BYTE *)mod, sz)) ok = TRUE;
    if (patch_rva((BYTE *)mod)) ok = TRUE;
    return ok;
}

static HMODULE real_ux = NULL;

static BOOL load_real_ux(void)
{
    wchar_t path[MAX_PATH];

    if (real_ux) return TRUE;
    if (!GetSystemDirectoryW(path, MAX_PATH)) return FALSE;
    if (!PathAppendW(path, L"uxtheme.dll")) return FALSE;
    real_ux = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    return real_ux != NULL;
}

static BOOL resolve_slots(void)
{
    unsigned i;

    if (!load_real_ux()) return FALSE;

    for (i = 0; i < UX_THEME_EXPORT_COUNT; i++) {
        FARPROC p;
        if (kUxThemeExports[i].ord)
            p = GetProcAddress(real_ux, MAKEINTRESOURCEA(kUxThemeExports[i].ord));
        else
            p = GetProcAddress(real_ux, kUxThemeExports[i].name);
        if (!p) p = (FARPROC)UxThemeStub;
        g_slots[i] = (void *)p;
    }
    return TRUE;
}

#define WM_DISMISS (WM_APP + 0x4D48)

typedef struct {
    HWND main;
    HWND nag;
    HWND reg;
} qt_wins;

typedef void *(*qt_find_t)(UINT_PTR);
typedef void (*qt_void_t)(void *);
typedef void (*qt_en_t)(void *, bool);

static WNDPROC old_main = NULL;

static LRESULT CALLBACK main_sub(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_DISMISS) {
        HMODULE qt = GetModuleHandleW(L"Qt5Widgets.dll");
        qt_find_t find;
        qt_void_t accept;
        qt_void_t reject;
        qt_en_t seten;
        void *w;

        if (!qt) return 1;
        find = (qt_find_t)GetProcAddress(qt, "?find@QWidget@@SAPEAV1@_K@Z");
        accept = (qt_void_t)GetProcAddress(qt, "?accept@QDialog@@UEAAXXZ");
        reject = (qt_void_t)GetProcAddress(qt, "?reject@QDialog@@UEAAXXZ");
        seten = (qt_en_t)GetProcAddress(qt, "?setEnabled@QWidget@@QEAAX_N@Z");
        if (!find) return 1;

        if ((HWND)wp && accept) {
            w = find((UINT_PTR)wp);
            if (w) accept(w);
        }
        if ((HWND)lp && reject) {
            w = find((UINT_PTR)lp);
            if (w) reject(w);
        }
        if (seten) {
            w = find((UINT_PTR)hwnd);
            if (w) seten(w, true);
        }
        EnableWindow(hwnd, TRUE);
        return 1;
    }
    return CallWindowProcW(old_main, hwnd, msg, wp, lp);
}

static BOOL CALLBACK enum_wins(HWND hwnd, LPARAM p)
{
    qt_wins *w = (qt_wins *)p;
    wchar_t cls[64], title[256];
    DWORD pid;

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;

    GetClassNameW(hwnd, cls, 64);
    GetWindowTextW(hwnd, title, 256);

    if (!lstrcmpW(cls, L"Qt51519QWindowIcon") && wcsstr(title, L"MediaHuman"))
        w->main = hwnd;
    if (!lstrcmpW(cls, L"Qt51519QWindow") && !lstrcmpW(title, L"YouTube Downloader"))
        w->nag = hwnd;
    if (!lstrcmpW(cls, L"Qt51519QWindowIcon") && !lstrcmpW(title, L"Registration"))
        w->reg = hwnd;
    return TRUE;
}

static void dismiss_nag(qt_wins *w)
{
    if (!w->main) return;
    if (!w->nag && !w->reg) return;
    if (!old_main)
        old_main = (WNDPROC)SetWindowLongPtrW(w->main, GWLP_WNDPROC, (LONG_PTR)main_sub);
    if (old_main)
        SendMessageW(w->main, WM_DISMISS, (WPARAM)w->nag, (LPARAM)w->reg);
}

static DWORD WINAPI nag_thread(LPVOID)
{
    int i;

    for (i = 0; i < 600; i++) {
        qt_wins w;
        RECT rc;

        w.main = w.nag = w.reg = NULL;
        EnumWindows(enum_wins, (LPARAM)&w);

        if (w.main) {
            GetWindowRect(w.main, &rc);
            if (rc.left < -10000 || rc.top < -10000 || (rc.right - rc.left) < 200) {
                ShowWindow(w.main, SW_RESTORE);
                SetWindowPos(w.main, NULL, 80, 80, 900, 600, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
        }

        if (w.main && w.nag && IsWindowVisible(w.nag)) {
            GetWindowRect(w.main, &rc);
            if ((rc.right - rc.left) > 400 && (rc.bottom - rc.top) > 300)
                dismiss_nag(&w);
        } else if (w.main && w.reg && IsWindowVisible(w.reg)) {
            dismiss_nag(&w);
        }

        Sleep(100);
    }
    return 0;
}

static DWORD WINAPI splash_thread(LPVOID)
{
    Sleep(300);
    MessageBoxW(NULL, L"Cracked by \"github.com/ofkits1\"", L"YouTube Downloader",
        MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
    return 0;
}

static DWORD WINAPI patch_thread(LPVOID)
{
    int i, hits = 0;

    for (i = 0; i < 3000; i++) {
        if (GetModuleHandleW(TARGET)) {
            if (do_patch()) hits++;
            if (hits >= 3) return 0;
        }
        Sleep(5);
    }
    return hits ? 0 : 1;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID)
{
    HANDLE t;

    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    DisableThreadLibraryCalls(inst);
    if (!resolve_slots()) return FALSE;

    t = CreateThread(NULL, 0, splash_thread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    t = CreateThread(NULL, 0, patch_thread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    t = CreateThread(NULL, 0, nag_thread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    return TRUE;
}
