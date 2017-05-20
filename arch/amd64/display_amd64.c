#include <stdio.h>

#include "common.h"
#include "arch.h"

#include "display.h"
#include "printfmt.h"

extern struct options_t options;

static void _dump_seg(const char *header, struct kvm_segment segment, const char *trailer) {
	printf("%sbase = %08x, limit = %08x, selector = %04x, type = %02x, present = %d\n"
		"    dpl = %d, db = %d, s = %d, l = %d, g = %d, avl = %d%s",
		header,
		segment.base, segment.limit, segment.selector, segment.type, segment.present,
		segment.dpl, segment.db, segment.s, segment.l, segment.g, segment.avl,
		trailer
	);
}

static void _dump_dtable(const char* table_name, struct kvm_dtable table) {
	printf("%s: base = %08x, limit = %08x\n",
		table_name, table.base, table.limit);
}

void display_amd64(
		const struct proc_info_t *const info)
{
	const struct kvm_regs   *regs   = &info->regs;
	const struct kvm_sregs  *sregs  = &info->sregs;
	const struct user_fpregs_struct_amd64 *fpregs = &info->fpregs_struct;

	const struct kvm_regs   *old_regs   = &info->old_regs;
	const struct kvm_sregs  *old_sregs  = &info->old_sregs;
	const struct user_fpregs_struct_amd64 *old_fpregs = &info->old_fpregs_struct;

	if (options.allregs) printf("GP Regs:\n");

	PRINTREG64("rax: ", rax, regs, old_regs, "\t");
	PRINTREG64("rbx: ", rbx, regs, old_regs, "\t");
	PRINTREG64("rcx: ", rcx, regs, old_regs, "\t");
	PRINTREG64("rdx: ", rdx, regs, old_regs, "\n");

	PRINTREG64("rsi: ", rsi, regs, old_regs, "\t");
	PRINTREG64("rdi: ", rdi, regs, old_regs, "\t");
	PRINTREG64("r8 : ", r8 , regs, old_regs, "\t");
	PRINTREG64("r9 : ", r9 , regs, old_regs, "\n");

	PRINTREG64("r10: ", r10, regs, old_regs, "\t");
	PRINTREG64("r11: ", r11, regs, old_regs, "\t");
	PRINTREG64("r12: ", r12, regs, old_regs, "\t");
	PRINTREG64("r13: ", r13, regs, old_regs, "\n");

	PRINTREG64("r14: ", r14, regs, old_regs, "\t");
	PRINTREG64("r15: ", r15, regs, old_regs, "\n");

	if (options.allregs) {
		PRINTSEG("cs : ", cs, sregs, old_sregs, "\n");
		PRINTSEG("ss : ", ss, sregs, old_sregs, "\n");
		PRINTSEG("ds : ", ds, sregs, old_sregs, "\n");
		PRINTSEG("es : ", es, sregs, old_sregs, "\n");
		PRINTSEG("fs : ", fs, sregs, old_sregs, "\n");
		PRINTSEG("gs : ", gs, sregs, old_sregs, "\n");
	}

	PRINTREG64("rip: ", rip, regs, old_regs, "\t");
	PRINTREG64("rsp: ", rsp, regs, old_regs, "\t");
	PRINTREG64("rbp: ", rbp, regs, old_regs, "\n");

	PRINTREG64("flags: ", rflags, regs, old_regs, " ");

	const uint8_t of = (regs->rflags & 0x800) >> 11;
	const uint8_t old_of = (old_regs->rflags & 0x800) >> 11;

	const uint8_t df = (regs->rflags & 0x400) >> 10;
	const uint8_t old_df = (old_regs->rflags & 0x400) >> 10;

	const uint8_t sf = (regs->rflags & 0x80) >> 7;
	const uint8_t old_sf = (regs->rflags & 0x80) >> 7;

	const uint8_t zf = (regs->rflags & 0x40) >> 6;
	const uint8_t old_zf = (old_regs->rflags & 0x40) >> 6;

	const uint8_t af = (regs->rflags & 0x10) >> 4;
	const uint8_t old_af = (old_regs->rflags & 0x10) >> 4;

	const uint8_t pf = (regs->rflags & 4) >> 2;
	const uint8_t old_pf = (old_regs->rflags & 4) >> 2;

	const uint8_t cf = regs->rflags & 1;
	const uint8_t old_cf = old_regs->rflags & 1;

	printf("[");
	PRINTBIT("cf:", cf, old_cf, ", ");
	PRINTBIT("zf:", zf, old_zf, ", ");
	PRINTBIT("of:", of, old_of, ", ");
	PRINTBIT("sf:", sf, old_sf, ", ");
	PRINTBIT("pf:", pf, old_pf, ", ");
	PRINTBIT("af:", af, old_af, ", ");
	PRINTBIT("df:", df, old_df, "");
	printf("]\n");

	if (options.allregs) {
		printf("FP Regs:\n");
		PRINTREG64("rip: ", rip, fpregs, old_fpregs, "\t");
		PRINTREG64("rdp: ", rdp, fpregs, old_fpregs, "\t");
		PRINTREG32("mxcsr: ", mxcsr, fpregs, old_fpregs, "\t");
		PRINTREG32("mxcsr_mask:", mxcr_mask, fpregs, old_fpregs, "\n");

		PRINTREG16("cwd: ", cwd, fpregs, old_fpregs, "\t");
		PRINTREG16("swd: ", swd, fpregs, old_fpregs, "\t");
		PRINTREG16("ftw: ", ftw, fpregs, old_fpregs, "\t");
		PRINTREG16("fop: ", fop, fpregs, old_fpregs, "\n");

		printf("st_space:\n");
		for (uint32_t i = 0; i < 32/4; ++i) {
			printf("0x%02x:\t", i * 0x10);
			for (uint32_t j = i*4; j < i*4 + 4; ++j) {
				DUMPREG32(st_space[j], fpregs, old_fpregs);
				printf("\t");
			}
			printf("\n");
		}

		printf("xmm_space:\n");
		for (uint32_t i = 0; i < 64/4; ++i) {
			printf("0x%02x:\t", i * 0x10);
			for (uint32_t j = i*4; j < i*4 + 4; ++j) {
				DUMPREG32(xmm_space[j], fpregs, old_fpregs);
				printf("\t");
			}
			printf("\n");
		}
	}
	//
	// 5 is sigtrap, which is expected, -1 is initial value
	if (info->sig != 5 && info->sig != -1) {
		printf("Process died with signal: %d\n", info->sig);
		printf("Exited: %ld\n", info->exit_code);
	}
}
