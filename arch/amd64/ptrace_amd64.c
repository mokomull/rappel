#include <sys/ptrace.h>
#include <linux/elf.h>

#include "common.h"
#include "arch.h"

void ptrace_collect_regs_amd64(
		const int vcpu_fd,
		struct proc_info_t *const info)
{
	info->old_regs = info->regs;
	info->old_sregs = info->sregs;

	REQUIRE(ioctl(vcpu_fd, KVM_GET_REGS, &info->regs) == 0);
	REQUIRE(ioctl(vcpu_fd, KVM_GET_SREGS, &info->sregs) == 0);

	info->exit_code = -1;
}

void ptrace_reset_amd64(
		const int vcpu_fd,
		const unsigned long start)
{
	struct kvm_regs regs;
	REQUIRE(ioctl(vcpu_fd, KVM_GET_REGS, &regs) == 0);
	regs.rip = start;
	REQUIRE(ioctl(vcpu_fd, KVM_SET_REGS, &regs) == 0);
}
