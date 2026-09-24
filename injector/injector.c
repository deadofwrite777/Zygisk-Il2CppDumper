#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

struct a64regs {
    unsigned long long x[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

static int regs_get(pid_t p, struct a64regs *r) {
    struct iovec v = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, p, (void*)1, &v);
}

static int regs_set(pid_t p, struct a64regs *r) {
    struct iovec v = { r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, p, (void*)1, &v);
}

static unsigned long long find_rxp_base(pid_t pid, const char *name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name) && strstr(line, "r-xp")) {
            unsigned long long b;
            sscanf(line, "%llx-", &b);
            fclose(f);
            return b;
        }
    }
    fclose(f);
    return 0;
}

static int find_containing_lib(pid_t pid, unsigned long long addr,
                               unsigned long long *base, char *out, int outsz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s, e;
        if (sscanf(line, "%llx-%llx", &s, &e) == 2 && addr >= s && addr < e) {
            *base = s;
            char *p = strrchr(line, '/');
            if (p) {
                p++;
                char *nl = strchr(p, '\n'); if (nl) *nl = 0;
                char *sp2 = strchr(p, ' '); if (sp2) *sp2 = 0;
                strncpy(out, p, outsz - 1);
            }
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <so_path>\n", argv[0]);
        return 1;
    }
    pid_t tgt = atoi(argv[1]);
    const char *lib = argv[2];

    printf("[*] Target PID %d | Library %s\n", tgt, lib);

    void *my_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!my_dlopen) { fprintf(stderr, "[-] dlsym dlopen\n"); return 1; }
    printf("[+] Our dlopen: %p\n", my_dlopen);

    unsigned long long my_base = 0;
    char libname[256] = {0};
    if (find_containing_lib(getpid(), (unsigned long long)my_dlopen,
                            &my_base, libname, sizeof(libname)) < 0) {
        fprintf(stderr, "[-] Can't locate dlopen's library in self\n");
        return 1;
    }
    unsigned long long offset = (unsigned long long)my_dlopen - my_base;
    printf("[+] dlopen lives in '%s', offset 0x%llx (our base 0x%llx)\n",
           libname, offset, my_base);

    unsigned long long tgt_base = find_rxp_base(tgt, libname);
    if (!tgt_base) {
        /* libdl.so not mapped separately in target — dlopen lives in linker64 */
        unsigned long long our_linker = find_rxp_base(getpid(), "linker64");
        unsigned long long tgt_linker = find_rxp_base(tgt, "linker64");
        if (our_linker && tgt_linker) {
            printf("[*] Falling back to linker64: ours=0x%llx target=0x%llx\n",
                   our_linker, tgt_linker);
            void *handle = dlopen("libdl.so", 2);
            if (handle) {
                void *real_dlopen = dlsym(handle, "__loader_dlopen");
                if (!real_dlopen) real_dlopen = dlsym(handle, "dlopen");
                if (real_dlopen) {
                    unsigned long long rdl = (unsigned long long)real_dlopen;
                    if (rdl >= our_linker) {
                        offset = rdl - our_linker;
                        tgt_base = tgt_linker;
                        printf("[+] Resolved via linker64, offset 0x%llx\n", offset);
                    }
                }
            }
        }
        if (!tgt_base) {
            /* Last resort: try libc.so */
            unsigned long long our_libc = find_rxp_base(getpid(), "libc.so");
            unsigned long long tgt_libc = find_rxp_base(tgt, "libc.so");
            if (our_libc && tgt_libc) {
                offset = (unsigned long long)my_dlopen - our_libc;
                tgt_base = tgt_libc;
                printf("[+] Fallback to libc.so: offset 0x%llx\n", offset);
            }
        }
        if (!tgt_base) {
            fprintf(stderr, "[-] Cannot locate dlopen in target via any method\n");
            return 1;
        }
    }
    unsigned long long tgt_dlopen = tgt_base + offset;
    printf("[+] Target base 0x%llx -> dlopen 0x%llx\n", tgt_base, tgt_dlopen);

    if (ptrace(PTRACE_ATTACH, tgt, NULL, NULL) < 0) {
        perror("[-] attach"); return 1;
    }
    int st; waitpid(tgt, &st, 0);
    printf("[+] Attached\n");

    struct a64regs orig, mod;
    if (regs_get(tgt, &orig) < 0) {
        perror("[-] getregs");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    printf("[+] Saved regs  PC=0x%llx SP=0x%llx\n", orig.pc, orig.sp);

    unsigned long long sa = (orig.sp - 512) & ~0xFULL;
    char buf[256] = {0};
    strncpy(buf, lib, sizeof(buf) - 1);
    struct iovec lv = { buf, strlen(lib)+1 };
    struct iovec rv = { (void*)sa, strlen(lib)+1 };
    if (process_vm_writev(tgt, &lv, 1, &rv, 1, 0) < 0) {
        perror("[-] writev");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    printf("[+] Path written at 0x%llx\n", sa);

    memcpy(&mod, &orig, sizeof(mod));
    mod.x[0]  = sa;
    mod.x[1]  = 2;
    mod.pc    = tgt_dlopen;
    mod.x[30] = 0;

    if (regs_set(tgt, &mod) < 0) {
        perror("[-] setregs");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    printf("[+] Regs set. Running dlopen...\n");

    ptrace(PTRACE_CONT, tgt, NULL, NULL);
    waitpid(tgt, &st, 0);
    printf("[+] Stopped. Signal %d\n", WSTOPSIG(st));

    struct a64regs after;
    regs_get(tgt, &after);
    printf("[+] dlopen returned 0x%llx\n", after.x[0]);

    if (after.x[0] == 0)
        printf("[-] FAILED. Check logcat for dlerror.\n");
    else
        printf("[+] SUCCESS handle 0x%llx\n", after.x[0]);

    regs_set(tgt, &orig);
    ptrace(PTRACE_DETACH, tgt, NULL, NULL);
    printf("[+] Restored & detached.\n");
    return 0;
}
