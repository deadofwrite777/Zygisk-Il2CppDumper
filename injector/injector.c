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

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <so_path>\n", argv[0]);
        return 1;
    }
    pid_t tgt = atoi(argv[1]);
    const char *lib = argv[2];

    printf("[*] Target PID %d | Library %s\n", tgt, lib);

    /* --- Find dlopen via libc.so (same binary in both processes) --- */
    unsigned long long our_libc = find_rxp_base(getpid(), "/libc.so");
    unsigned long long tgt_libc = find_rxp_base(tgt, "/libc.so");

    if (!our_libc || !tgt_libc) {
        fprintf(stderr, "[-] libc.so not found. ours=0x%llx target=0x%llx\n",
                our_libc, tgt_libc);
        return 1;
    }
    printf("[+] libc.so: ours=0x%llx target=0x%llx\n", our_libc, tgt_libc);

    /* Try multiple dlopen symbols in order of preference */
    void *dlopen_ptr = NULL;
    const char *sym_name = NULL;

    /* 1. __loader_dlopen — the real implementation inside the linker,
          but sometimes accessible via libc's PLT */
    dlopen_ptr = dlsym(RTLD_DEFAULT, "__loader_dlopen");
    if (dlopen_ptr) { sym_name = "__loader_dlopen"; }

    /* 2. dlopen — standard */
    if (!dlopen_ptr) {
        dlopen_ptr = dlsym(RTLD_DEFAULT, "dlopen");
        if (dlopen_ptr) sym_name = "dlopen";
    }

    if (!dlopen_ptr) {
        fprintf(stderr, "[-] Cannot resolve any dlopen symbol\n");
        return 1;
    }

    unsigned long long dlopen_addr = (unsigned long long)dlopen_ptr;
    printf("[+] Resolved '%s' at 0x%llx in our process\n", sym_name, dlopen_addr);

    /* Check if dlopen lives within our libc range */
    unsigned long long offset;
    unsigned long long tgt_base;

    if (dlopen_addr >= our_libc && dlopen_addr < our_libc + 0x200000) {
        /* dlopen is inside libc.so — perfect, same binary = same offset */
        offset = dlopen_addr - our_libc;
        tgt_base = tgt_libc;
        printf("[+] '%s' is in libc.so at offset 0x%llx\n", sym_name, offset);
    } else {
        /* dlopen is NOT in libc — it's in linker64 or libdl.so
           We need to use a different strategy: find a libc function
           that CALLS dlopen, or use mmap+shellcode */
        printf("[*] '%s' at 0x%llx is NOT in libc (libc=0x%llx)\n",
               sym_name, dlopen_addr, our_libc);

        /* Try to find it in linker64 */
        unsigned long long our_linker = find_rxp_base(getpid(), "linker64");
        unsigned long long tgt_linker = find_rxp_base(tgt, "linker64");

        if (our_linker && tgt_linker &&
            dlopen_addr >= our_linker && dlopen_addr < our_linker + 0x200000) {
            offset = dlopen_addr - our_linker;
            tgt_base = tgt_linker;
            printf("[+] '%s' is in linker64 at offset 0x%llx\n", sym_name, offset);
            printf("[!] WARNING: linker64 may differ between processes!\n");
            printf("[!] Our linker: 0x%llx, Target linker: 0x%llx\n",
                   our_linker, tgt_linker);

            /* Verify both linkers are the same size as a sanity check */
            char our_path[64], tgt_path2[64];
            snprintf(our_path, 64, "/proc/%d/maps", getpid());
            snprintf(tgt_path2, 64, "/proc/%d/maps", tgt);

            /* Read both maps and compare linker64 region sizes */
            FILE *f1 = fopen(our_path, "r");
            FILE *f2 = fopen(tgt_path2, "r");
            unsigned long long our_end = 0, tgt_end = 0;
            char line[512];
            if (f1) {
                while (fgets(line, 512, f1)) {
                    if (strstr(line, "linker64") && strstr(line, "r-xp")) {
                        unsigned long long s, e;
                        sscanf(line, "%llx-%llx", &s, &e);
                        our_end = e;
                        break;
                    }
                }
                fclose(f1);
            }
            if (f2) {
                while (fgets(line, 512, f2)) {
                    if (strstr(line, "linker64") && strstr(line, "r-xp")) {
                        unsigned long long s, e;
                        sscanf(line, "%llx-%llx", &s, &e);
                        tgt_end = e;
                        break;
                    }
                }
                fclose(f2);
            }
            unsigned long long our_sz = our_end - our_linker;
            unsigned long long tgt_sz = tgt_end - tgt_linker;
            printf("[*] linker64 sizes: ours=%llu target=%llu\n", our_sz, tgt_sz);
            if (our_sz != tgt_sz) {
                fprintf(stderr, "[-] LINKER SIZE MISMATCH — different binaries! "
                        "Cannot safely compute offset.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "[-] Cannot locate '%s' in any shared library\n", sym_name);
            return 1;
        }
    }

    unsigned long long tgt_dlopen = tgt_base + offset;
    printf("[+] Target dlopen: 0x%llx (base 0x%llx + offset 0x%llx)\n",
           tgt_dlopen, tgt_base, offset);

    /* --- Attach --- */
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

    /* --- Write library path to target stack --- */
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

    /* --- Set registers for dlopen(path, RTLD_NOW) --- */
    memcpy(&mod, &orig, sizeof(mod));
    mod.x[0]  = sa;          /* arg1: filename */
    mod.x[1]  = 2;           /* arg2: RTLD_NOW */
    mod.x[2]  = 0;           /* x2: clear (some dlopen variants take 3 args) */
    mod.x[3]  = 0;           /* x3: clear */
    mod.pc    = tgt_dlopen;  /* jump to dlopen */
    mod.x[30] = 0;           /* LR=0 → will SIGSEGV on return, we catch it */

    if (regs_set(tgt, &mod) < 0) {
        perror("[-] setregs");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    printf("[+] Regs set. Running dlopen...\n");

    /* --- Execute dlopen, catch the return-to-0 SIGSEGV --- */
    ptrace(PTRACE_CONT, tgt, NULL, NULL);
    waitpid(tgt, &st, 0);
    printf("[+] Stopped. Signal %d\n", WSTOPSIG(st));

    /* --- Read return value --- */
    struct a64regs after;
    regs_get(tgt, &after);
    printf("[+] dlopen returned 0x%llx\n", after.x[0]);

    if (after.x[0] == 0)
        printf("[-] FAILED. Check logcat for dlerror.\n");
    else
        printf("[+] SUCCESS handle 0x%llx\n", after.x[0]);

    /* --- Restore and detach --- */
    regs_set(tgt, &orig);
    ptrace(PTRACE_DETACH, tgt, NULL, NULL);
    printf("[+] Restored & detached.\n");
    return 0;
}
