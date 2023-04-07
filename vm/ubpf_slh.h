#ifndef UBPF_SLH_H
#define UBPF_SLH_H

#include "ebpf.h"
#include "ubpf_int.h"
#include "ubpf_jit_x86_64.h"
#include <stdint.h>

/* enum ubpf_registers */
/* { */
/*     rax, */
/*     rbx, */
/*     rcx, */
/*     rdx, */
/*     rsi, */
/*     rdi, */
/*     rbp, */
/*     rsp, */
/*     r8, */
/*     r9, */
/*     r10, */
/*     r11, */
/*     r12, */
/*     r13, */
/*     r14, */
/*     r15 */
/* }; */

char*
register_name(uint8_t reg);
char*
instruct_opname(uint8_t opcode);
int
parse_ebpf_inst(struct ubpf_vm* vm);
void
print_inst(struct ubpf_vm* vm);
void
print_cfg(struct ubpf_basic_block* bb);
void
truncate_cfg(struct ubpf_vm* vm, struct ubpf_basic_block* bb, uint32_t index, uint32_t target_pc);
void
instrument_slh(const struct ubpf_vm* vm, struct ubpf_basic_block* bb, struct ebpf_inst* insts);

#endif /* UBPF_SLH_H */
