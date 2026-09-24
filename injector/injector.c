#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>

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

/* Execute a syscall in the target process via ptrace.
   Sets x8=sysno, x0-x5=args, PC to a SVC instruction,
   single-steps, returns x0 (syscall result). */
static long long remote_syscall(pid_t tgt, struct a64regs *orig,
                                long long sysno,
                                long long a0, long long a1, long long a2,
                                long long a3, long long a4, long long a5) {
    struct a64regs mod;
    memcpy(&mod, orig, sizeof(mod));
    mod.x[8]  = sysno;
    mod.x[0]  = a0;
    mod.x[1]  = a1;
    mod.x[2]  = a2;
    mod.x[3]  = a3;
    mod.x[4]  = a4;
    mod.x[5]  = a5;

    /* We need a SVC #0 instruction somewhere in the target's memory.
       The linker64 or libc definitely contains SVC instructions.
       Scan target's memory for one. SVC #0 = 0xD4000001 on ARM64. */

    /* Actually, simpler: write a SVC;BRK pair onto the stack
       (below SP, in the red zone equivalent) */
    unsigned long long code_addr = (orig->sp - 256) & ~0xFULL;
    unsigned int svc_brk[2] = {
        0xD4000001,  /* SVC #0 */
        0xD4200000   /* BRK #0 (will trap back to ptrace) */
    };
    struct iovec lv = { svc_brk, sizeof(svc_brk) };
    struct iovec rv = { (void*)code_addr, sizeof(svc_brk) };
    if (process_vm_writev(tgt, &lv, 1, &rv, 1, 0) < 0) {
        perror("[-] writev svc");
        return -1;
    }

    mod.pc = code_addr;
    mod.x[30] = 0; /* LR doesn't matter, we trap on BRK */

    if (regs_set(tgt, &mod) < 0) {
        perror("[-] setregs syscall");
        return -1;
    }

    /* Continue until the SIGTRAP from BRK */
    ptrace(PTRACE_CONT, tgt, NULL, NULL);
    int st;
    waitpid(tgt, &st, 0);

    /* Read result from x0 */
    struct a64regs after;
    regs_get(tgt, &after);

    /* Restore original regs */
    regs_set(tgt, orig);

    return (long long)after.x[0];
}

/* Find the GOT entry for dlopen in a loaded library in the target.
   We scan the target's loaded libraries for one that imports dlopen,
   read its GOT to get the resolved dlopen address. */
static unsigned long long find_dlopen_in_target(pid_t tgt) {
    /* Read target's maps to find libraries that might import dlopen */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", tgt);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) return 0;

    char line[512];
    /* Look for libdl.so — even if it's tiny, it has the dlopen PLT resolved */
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libdl.so") && strstr(line, "xp")) {
            unsigned long long base;
            sscanf(line, "%llx-", &base);
            fclose(maps);
            printf("[+] Found libdl.so in target at 0x%llx\n", base);
            /* dlopen is typically the first or second function.
               On Android, libdl.so is a tiny shim where dlopen
               is at a very small offset (usually 0x1000 + small PLT).
               But we don't know the exact offset...
               
               Actually, let's try a completely different approach. */
            return 0; /* Fall through to shellcode approach */
        }
    }
    fclose(maps);
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

    /* --- Attach --- */
    if (ptrace(PTRACE_ATTACH, tgt, NULL, NULL) < 0) {
        perror("[-] attach"); return 1;
    }
    int st;
    waitpid(tgt, &st, 0);
    printf("[+] Attached\n");

    struct a64regs orig;
    if (regs_get(tgt, &orig) < 0) {
        perror("[-] getregs");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    printf("[+] Saved regs  PC=0x%llx SP=0x%llx\n", orig.pc, orig.sp);

    /* --- Step 1: mmap executable memory in target via syscall --- */
    /* mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    /* ARM64 syscall number for mmap is 222 */
    long long mmap_result = remote_syscall(tgt, &orig,
        222,                                    /* __NR_mmap */
        0,                                      /* addr = NULL */
        4096,                                   /* length = 4096 */
        PROT_READ | PROT_WRITE | PROT_EXEC,     /* prot = RWX */
        MAP_PRIVATE | MAP_ANONYMOUS,             /* flags */
        -1,                                      /* fd = -1 */
        0                                        /* offset = 0 */
    );

    if (mmap_result <= 0 || mmap_result == (long long)-1) {
        fprintf(stderr, "[-] remote mmap failed: 0x%llx\n",
                (unsigned long long)mmap_result);
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }
    unsigned long long rwx_page = (unsigned long long)mmap_result;
    printf("[+] mmap'd RWX page at 0x%llx in target\n", rwx_page);

    /* --- Step 2: Write the library path into the RWX page --- */
    char path_buf[256] = {0};
    strncpy(path_buf, lib, sizeof(path_buf) - 1);
    /* Path goes at offset 0x200 in the page */
    unsigned long long path_addr = rwx_page + 0x200;
    {
        struct iovec lv = { path_buf, strlen(lib) + 1 };
        struct iovec rv = { (void*)path_addr, strlen(lib) + 1 };
        if (process_vm_writev(tgt, &lv, 1, &rv, 1, 0) < 0) {
            perror("[-] writev path");
            ptrace(PTRACE_DETACH, tgt, NULL, NULL);
            return 1;
        }
    }
    printf("[+] Library path written at 0x%llx\n", path_addr);

    /* --- Step 3: Write shellcode that calls dlopen via __NR_openat trick ---
       
       Actually, we can't call dlopen via syscall — it's a userspace function.
       But we CAN use the target's own libc to call it.
       
       The trick: find the target's libc.so base, then find __libc_dlopen_mode
       by scanning for known byte patterns... that's fragile.
       
       SIMPLEST RELIABLE APPROACH:
       Write shellcode that does:
         1. Load the path address into x0
         2. Load RTLD_NOW (2) into x1  
         3. BLR to the dlopen address
         4. BRK #0 to trap back to us
       
       We still need dlopen's address. BUT — we can get it by reading the
       target's own GOT. Every Android process links against libdl.so,
       and the linker resolves dlopen's GOT entry at load time.
       
       Let's find dlopen's resolved address from the target's OWN memory. */

    /* --- Step 3 (revised): Read dlopen's address from target's GOT ---
       
       We search the target's /proc/PID/maps for libdl.so,
       then read its ELF headers to find the GOT entry for dlopen,
       then read that GOT entry from /proc/PID/mem to get the
       resolved runtime address. */
    
    /* Find libdl.so's load base and file path in target */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", tgt);
    FILE *maps_f = fopen(maps_path, "r");
    if (!maps_f) {
        perror("[-] open maps");
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }

    unsigned long long libdl_base = 0;
    char libdl_path[256] = {0};
    char mline[512];
    while (fgets(mline, sizeof(mline), maps_f)) {
        /* Look for ANY mapping of libdl.so (not just executable) */
        if (strstr(mline, "libdl.so")) {
            sscanf(mline, "%llx-", &libdl_base);
            char *slash = strchr(mline, '/');
            if (slash) {
                char *nl = strchr(slash, '\n');
                if (nl) *nl = 0;
                strncpy(libdl_path, slash, sizeof(libdl_path) - 1);
            }
            break;
        }
    }
    fclose(maps_f);

    unsigned long long dlopen_addr = 0;

    if (libdl_base && libdl_path[0]) {
        printf("[+] Target libdl.so at 0x%llx (%s)\n", libdl_base, libdl_path);

        /* Read the ELF file from disk to find dlopen's symbol */
        FILE *elf_f = fopen(libdl_path, "rb");
        if (elf_f) {
            Elf64_Ehdr ehdr;
            fread(&ehdr, sizeof(ehdr), 1, elf_f);

            /* Read section headers to find .dynsym and .dynstr */
            Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
            fseek(elf_f, ehdr.e_shoff, SEEK_SET);
            fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, elf_f);

            /* Find .dynsym section */
            for (int i = 0; i < ehdr.e_shnum; i++) {
                if (shdrs[i].sh_type == SHT_DYNSYM) {
                    int str_idx = shdrs[i].sh_link;
                    /* Read string table */
                    char *strtab = malloc(shdrs[str_idx].sh_size);
                    fseek(elf_f, shdrs[str_idx].sh_offset, SEEK_SET);
                    fread(strtab, 1, shdrs[str_idx].sh_size, elf_f);

                    /* Read symbol table */
                    int nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);
                    Elf64_Sym *syms = malloc(shdrs[i].sh_size);
                    fseek(elf_f, shdrs[i].sh_offset, SEEK_SET);
                    fread(syms, sizeof(Elf64_Sym), nsyms, elf_f);

                    for (int j = 0; j < nsyms; j++) {
                        const char *name = strtab + syms[j].st_name;
                        if (strcmp(name, "dlopen") == 0 && syms[j].st_value != 0) {
                            dlopen_addr = libdl_base + syms[j].st_value;
                            printf("[+] dlopen symbol at offset 0x%llx -> target addr 0x%llx\n",
                                   (unsigned long long)syms[j].st_value, dlopen_addr);
                            break;
                        }
                    }
                    free(syms);
                    free(strtab);
                    break;
                }
            }
            free(shdrs);
            fclose(elf_f);
        }
    }

    /* Fallback: scan target's linker64 for __dl_dlopen pattern */
    if (!dlopen_addr) {
        printf("[*] libdl.so approach failed. Trying to read dlopen from target's libc PLT...\n");

        /* Find libc.so in target */
        maps_f = fopen(maps_path, "r");
        if (maps_f) {
            unsigned long long libc_base = 0;
            char libc_path_buf[256] = {0};
            while (fgets(mline, sizeof(mline), maps_f)) {
                if (strstr(mline, "libc.so") && !strstr(mline, "libc_malloc")) {
                    sscanf(mline, "%llx-", &libc_base);
                    char *slash = strchr(mline, '/');
                    if (slash) {
                        char *nl = strchr(slash, '\n');
                        if (nl) *nl = 0;
                        strncpy(libc_path_buf, slash, sizeof(libc_path_buf) - 1);
                    }
                    break;
                }
            }
            fclose(maps_f);

            if (libc_base && libc_path_buf[0]) {
                printf("[+] Target libc.so at 0x%llx (%s)\n", libc_base, libc_path_buf);
                FILE *elf_f = fopen(libc_path_buf, "rb");
                if (elf_f) {
                    Elf64_Ehdr ehdr;
                    fread(&ehdr, sizeof(ehdr), 1, elf_f);
                    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
                    fseek(elf_f, ehdr.e_shoff, SEEK_SET);
                    fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, elf_f);

                    for (int i = 0; i < ehdr.e_shnum; i++) {
                        if (shdrs[i].sh_type == SHT_DYNSYM) {
                            int str_idx = shdrs[i].sh_link;
                            char *strtab = malloc(shdrs[str_idx].sh_size);
                            fseek(elf_f, shdrs[str_idx].sh_offset, SEEK_SET);
                            fread(strtab, 1, shdrs[str_idx].sh_size, elf_f);

                            int nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);
                            Elf64_Sym *syms = malloc(shdrs[i].sh_size);
                            fseek(elf_f, shdrs[i].sh_offset, SEEK_SET);
                            fread(syms, sizeof(Elf64_Sym), nsyms, elf_f);

                            for (int j = 0; j < nsyms; j++) {
                                const char *name = strtab + syms[j].st_name;
                                if (strcmp(name, "dlopen") == 0 && syms[j].st_value != 0) {
                                    dlopen_addr = libc_base + syms[j].st_value;
                                    printf("[+] dlopen in libc at offset 0x%llx -> 0x%llx\n",
                                           (unsigned long long)syms[j].st_value, dlopen_addr);
                                    break;
                                }
                            }
                            free(syms);
                            free(strtab);
                            break;
                        }
                    }
                    free(shdrs);
                    fclose(elf_f);
                }
            }
        }
    }

    if (!dlopen_addr) {
        fprintf(stderr, "[-] Cannot find dlopen address in target\n");
        /* Clean up: munmap the RWX page */
        remote_syscall(tgt, &orig, 215, rwx_page, 4096, 0, 0, 0, 0);
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }

    printf("[+] Will call dlopen at 0x%llx\n", dlopen_addr);

    /* --- Step 4: Write shellcode into the RWX page ---
       
       ARM64 shellcode:
         LDR X0, [PC, #16]   ; load path_addr
         LDR X1, [PC, #16]   ; load RTLD_NOW  
         LDR X16, [PC, #16]  ; load dlopen_addr
         BLR X16              ; call dlopen
         BRK #0               ; trap back to ptrace
         .quad path_addr      ; 8 bytes
         .quad 2              ; 8 bytes (RTLD_NOW)
         .quad dlopen_addr    ; 8 bytes
    */
    unsigned int shellcode[] = {
        0x58000080,  /* LDR X0, [PC, #16]  - loads from pc+16 = offset 0x14 */
        0x58000081,  /* LDR X1, [PC, #16]  - loads from pc+16 = offset 0x18... */
    };
    /* Actually, LDR Xt, label uses a PC-relative offset that's tricky.
       Let me use a simpler approach — load immediates via MOVZ/MOVK */

    /* Build shellcode that loads 64-bit immediates into x0, x1, x16 */
    unsigned int sc[32];
    int idx = 0;

    /* MOV X0, path_addr (4 instructions: MOVZ + 3x MOVK) */
    sc[idx++] = 0xD2800000 | ((path_addr & 0xFFFF) << 5);           /* MOVZ X0, #imm16, LSL #0 */
    sc[idx++] = 0xF2A00000 | (((path_addr >> 16) & 0xFFFF) << 5);   /* MOVK X0, #imm16, LSL #16 */
    sc[idx++] = 0xF2C00000 | (((path_addr >> 32) & 0xFFFF) << 5);   /* MOVK X0, #imm16, LSL #32 */
    sc[idx++] = 0xF2E00000 | (((path_addr >> 48) & 0xFFFF) << 5);   /* MOVK X0, #imm16, LSL #48 */

    /* MOV X1, #2 (RTLD_NOW) */
    sc[idx++] = 0xD2800041;  /* MOVZ X1, #2 */

    /* MOV X16, dlopen_addr (4 instructions) */
    sc[idx++] = 0xD2800010 | ((dlopen_addr & 0xFFFF) << 5);         /* MOVZ X16, #imm16, LSL #0 */
    sc[idx++] = 0xF2A00010 | (((dlopen_addr >> 16) & 0xFFFF) << 5); /* MOVK X16, #imm16, LSL #16 */
    sc[idx++] = 0xF2C00010 | (((dlopen_addr >> 32) & 0xFFFF) << 5); /* MOVK X16, #imm16, LSL #32 */
    sc[idx++] = 0xF2E00010 | (((dlopen_addr >> 48) & 0xFFFF) << 5); /* MOVK X16, #imm16, LSL #48 */

    /* BLR X16 */
    sc[idx++] = 0xD63F0200;  /* BLR X16 */

    /* BRK #0 — trap back to ptrace */
    sc[idx++] = 0xD4200000;  /* BRK #0 */

    /* Write shellcode to the RWX page */
    {
        struct iovec lv = { sc, idx * 4 };
        struct iovec rv = { (void*)rwx_page, idx * 4 };
        if (process_vm_writev(tgt, &lv, 1, &rv, 1, 0) < 0) {
            perror("[-] writev shellcode");
            remote_syscall(tgt, &orig, 215, rwx_page, 4096, 0, 0, 0, 0);
            ptrace(PTRACE_DETACH, tgt, NULL, NULL);
            return 1;
        }
    }
    printf("[+] Shellcode written (%d instructions)\n", idx);

    /* --- Step 5: Execute shellcode --- */
    struct a64regs sc_regs;
    memcpy(&sc_regs, &orig, sizeof(sc_regs));
    sc_regs.pc = rwx_page;
    sc_regs.x[30] = 0;

    if (regs_set(tgt, &sc_regs) < 0) {
        perror("[-] setregs shellcode");
        remote_syscall(tgt, &orig, 215, rwx_page, 4096, 0, 0, 0, 0);
        ptrace(PTRACE_DETACH, tgt, NULL, NULL);
        return 1;
    }

    printf("[+] Executing shellcode at 0x%llx...\n", rwx_page);
    ptrace(PTRACE_CONT, tgt, NULL, NULL);
    waitpid(tgt, &st, 0);
    printf("[+] Stopped. Signal %d\n", WSTOPSIG(st));

    /* Read return value from x0 */
    struct a64regs after;
    regs_get(tgt, &after);
    printf("[+] dlopen returned 0x%llx\n", after.x[0]);

    if (after.x[0] == 0)
        printf("[-] FAILED. Check logcat for dlerror.\n");
    else
        printf("[+] SUCCESS! Library loaded, handle 0x%llx\n", after.x[0]);

    /* --- Cleanup: munmap the RWX page --- */
    /* __NR_munmap = 215 */
    remote_syscall(tgt, &orig, 215, rwx_page, 4096, 0, 0, 0, 0);
    printf("[+] RWX page cleaned up\n");

    /* --- Restore and detach --- */
    regs_set(tgt, &orig);
    ptrace(PTRACE_DETACH, tgt, NULL, NULL);
    printf("[+] Restored & detached.\n");
    return 0;
}
