// signal.cpp — Signal handling and crash diagnostics
#include "signal.hpp"
#include "log.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef __aarch64__
#include <ucontext.h>
#endif

namespace sig {

static std::atomic<bool>* s_shutdown = nullptr;

#ifdef __aarch64__
static void crash_handler(int sig, siginfo_t* si, void* ucv) {
    auto* uc = (ucontext_t*)ucv;
    void* pc = (void*)uc->uc_mcontext.pc;
    void* lr = (void*)uc->uc_mcontext.regs[30];
    fprintf(stderr, "\n=== SIGNAL %d ===\n  fault=%p pc=%p lr=%p\n",
            sig, si->si_addr, pc, lr);
    Dl_info di{};
    if (dladdr(pc, &di))
        fprintf(stderr, "  pc in: %s+0x%lx (%s)\n", di.dli_fname ?: "?",
                (unsigned long)((uintptr_t)pc - (uintptr_t)di.dli_fbase),
                di.dli_sname ?: "?");
    if (dladdr(lr, &di))
        fprintf(stderr, "  lr in: %s+0x%lx (%s)\n", di.dli_fname ?: "?",
                (unsigned long)((uintptr_t)lr - (uintptr_t)di.dli_fbase),
                di.dli_sname ?: "?");
    void** fp = (void**)uc->uc_mcontext.regs[29];
    for (int d = 0; d < 15 && fp; ++d) {
        void* prev_lr = fp[1];
        if (!prev_lr) break;
        Dl_info d2{};
        if (dladdr(prev_lr, &d2))
            fprintf(stderr, "  #%d %s+0x%lx (%s)\n", d, d2.dli_fname ?: "?",
                    (unsigned long)((uintptr_t)prev_lr - (uintptr_t)d2.dli_fbase),
                    d2.dli_sname ?: "?");
        if (fp[0] <= (void*)fp) break;
        fp = (void**)fp[0];
    }
    _exit(128 + sig);
}
#endif

static void sigint_handler(int) {
    if (s_shutdown) s_shutdown->store(true);
}

void install(std::atomic<bool>& shutdown_flag) {
    s_shutdown = &shutdown_flag;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

#ifdef __aarch64__
    struct sigaction sa{};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
#endif
}

void print_network_interfaces() {
    LOG_INFO("net", "network interfaces:");
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        LOG_ERROR("net", "getifaddrs failed: %s", strerror(errno));
        return;
    }
    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        LOG_INFO("net", "%-8s %s%s", ifa->ifa_name, buf,
                 (ifa->ifa_flags & IFF_LOOPBACK) ? " (lo)" : "");
    }
    freeifaddrs(ifap);
}

}  // namespace sig
