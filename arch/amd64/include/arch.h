#include <sys/uio.h>
#include <linux/kvm.h>

#define TRAP 0xcc // int3
#define TRAP_SZ 1

#define BITSTR "[bits 64]\n"

#define AMD64_INIT_PROC_INFO(i) \
	do {\
		(i).fpregs = (struct iovec) { .iov_base = &(i).fpregs_struct, .iov_len = sizeof((i).fpregs_struct) }; \
	} while (0)

struct user_fpregs_struct_amd64
{
	unsigned short int    cwd;
	unsigned short int    swd;
	unsigned short int    ftw;
	unsigned short int    fop;
	unsigned long long int rip;
	unsigned long long int rdp;
	unsigned int      mxcsr;
	unsigned int      mxcr_mask;
	unsigned int      st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
	unsigned int      xmm_space[64];  /* 16*16 bytes for each XMM-reg = 256 bytes */
	unsigned int      padding[24];
};

struct proc_info_t {
	pid_t pid;

    struct kvm_regs regs;
    struct kvm_regs old_regs;

    struct kvm_sregs sregs;
    struct kvm_sregs old_sregs;

    struct user_fpregs_struct_amd64 fpregs_struct;
    struct user_fpregs_struct_amd64 old_fpregs_struct;
	struct iovec fpregs;

	int sig;
	long exit_code;
};

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
