#include <stdio.h>
#include <unistd.h>

#include "common.h"
#include "arch.h"

void dump_state_amd64(
		const struct proc_info_t *const info)
{
	const struct user_fpregs_struct_amd64 *fpregs = &info->fpregs_struct;

	write_data(STDOUT_FILENO, &info->regs, sizeof(info->regs));
	write_data(STDOUT_FILENO, &info->sregs, sizeof(info->sregs));
	write_data(STDOUT_FILENO, (uint8_t *)fpregs, sizeof(struct user_fpregs_struct_amd64));
}
