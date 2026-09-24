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

/* Find the base address of an executable mapping containing `name`.
   Matches any line with 'xp' in the permissions (covers r-xp AND --xp). */
static unsigned long long find_exec_base(pid_t pid, const char *name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name) && strstr(line, "xp")) {
            unsigned long long b;
            sscanf(line, "%llx-", &b);
            fclose(f);
            return b;
        }
    }
    fclose(f);
    return 0;
}

/* Find the end address of an executable mapping containing `name`. */
static unsigned long long find_exec_end(pid_t pid, const char *name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name) && strstr(line, "xp")) {
            unsigned long long s, e;
            sscanf(line, "%llx-%llx", &s, &e);
            fclose(f);
            return e;
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

    /* --- Resolve dlopen in ourselves --- */
    void *my_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!my_dlopen) { fprintf(stderr, "[-] dlsym dlopen\n"); return 1; }
    printf("[+] Our dlopen: %p\n", my_dlopen);

    unsigned long long dlopen_addr = (unsigned long long)my_dlopen;

    /* --- Strategy: find which library contains dlopen, compute offset,
           find same library in target, apply offset --- */

    /* Try libc.so first (same binary in both processes on same Android) */
    unsigned long long our_libc = find_exec_base(getpid(), "libc.so");
    unsigned long long our_libc_end = find_exec_end(getpid(), "libc.so");
    unsigned long long tgt_libc = find_exec_base(tgt, "libc.so");

    printf("[*] libc.so: ours=0x%llx..0x%llx target=0x%llx\n",
           our_libc, our_libc_end, tgt_libc);

    unsigned long long offset = 0;
    unsigned long long tgt_base = 0;

    if (our_libc && tgt_libc && dlopen_addr >= our_libc && dlopen_addr < our_libc_end) {
        offset = dlopen_addr - our_libc;
        tgt_base = tgt_libc;
        printf("[+] dlopen is in libc.so, offset 0x%llx\n", offset);
    }

    /* If dlopen isn't in libc, try linker64 */
    if (!tgt_base) {
        unsigned long long our_linker = find_exec_base(getpid(), "linker64");
        unsigned long long our_linker_end = find_exec_end(getpid(), "linker64");
        unsigned long long tgt_linker = find_exec_base(tgt, "linker64");
        unsigned long long tgt_linker_end = find_exec_end(tgt, "linker64");

        printf("[*] linker64: ours=0x%llx..0x%llx target=0x%llx..0x%llx\n",
               our_linker, our_linker_end, tgt_linker, tgt_linker_end);

        if (our_linker && tgt_linker) {
            /* Verify both linkers are the same size */
            unsigned long long our_sz = our_linker_end - our_linker;
            unsigned long long tgt_sz = tgt_linker_end - tgt_linker;
            printf("[*] linker64 exec sizes: ours=%llu target=%llu\n", our_sz, tgt_sz);

            if (our_sz == tgt_sz) {
                /* Re-resolve dlopen — it might be a PLT stub in libdl.
                   Get the real implementation inside linker64 */
                void *handle = dlopen("libdl.so", RTLD_NOW);
                void *real_dlopen = NULL;
                if (handle) {
                    real_dlopen = dlsym(handle, "__loader_dlopen");
                    if (!real_dlopen) real_dlopen = dlsym(handle, "dlopen");
                }
                unsigned long long rdl = real_dlopen ? (unsigned long long)real_dlopen : dlopen_addr;

                if (rdl >= our_linker && rdl < our_linker_end) {
                    offset = rdl - our_linker;
                    tgt_base = tgt_linker;
                    printf("[+] dlopen is in linker64, offset 0x%llx\n", offset);
                } else {
                    printf("[*] dlopen at 0x%llx is NOT inside linker64 range\n", rdl);
                }
            } else {
                printf("[-] linker64 size mismatch! Cannot safely use offset.\n");
            }
        }
    }

    /* Last resort: use the containing-lib approach */
    if (!tgt_base) {
        unsigned long long my_base_auto = 0;
        char libname[256] = {0};
        if (find_containing_lib(getpid(), dlopen_addr, &my_base_auto, libname, sizeof(libname)) == 0) {
            printf("[*] dlopen is in '%s' at base 0x%llx\n", libname, my_base_auto);
            unsigned long long tgt_auto = find_exec_base(tgt, libname);
            if (tgt_auto) {
                offset = dlopen_addr - my_base_auto;
                tgt_base = tgt_auto;
                printf("[+] Found '%s' in target at 0x%llx, offset 0x%llx\n",
                       libname, tgt_auto, offset);
            }
        }
    }

    if (!tgt_base) {
        fprintf(stderr, "[-] Cannot locate dlopen in target via any method\n");
        return 1;
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
    mod.x[2]  = 0;           /* clear */
    mod.x[3]  = 0;           /* clear */
    mod.pc    = tgt_dlopen;  /* jump to dlopen */
    mod.x[30] = 0;           /* LR=0 -> SIGSEGV on return, we catch it */

    if (regs_set(tgt, &mod) < 0) {
        perror("[-] setregs");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    printf("[+] Regs set. Running dlopen...\n");

    /* --- Execute dlopen, wait for return-to-0 fault --- */
    ptrace(PTRACE_CONT, tgt, NULL, NULL);
    waitpid(tgt, &st, 0);
    printf("[+] Stopped. Signal %d\n", WSTOPSIG(st));

    /* --- Read return value (x0) --- */
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
