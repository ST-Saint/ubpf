#ifndef UBPF_SLH_H
#define UBPF_SLH_H

#include "ebpf.h"
#include "ubpf_int.h"
#include <stdint.h>

struct ubpf_basic_block
{
    /* the index of the first instruction in ubpf_vm->ebpf_inst */
    uint32_t index;
    uint32_t num_inst;
    struct ebpf_inst* insts;
    struct ubpf_basic_block *fallthrough, *jump;
};

struct ubpf_cfg
{
    struct ubpf_basic_block* entry;
    struct ubpf_basic_block* maps[65536];
};

enum Registers
{
    RAX,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RBP,
    RSP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
};

char*
register_name(uint32_t reg);

int
parse_ebpf_inst(struct ubpf_vm* vm);
void
print_cfg(struct ubpf_basic_block* bb, int depth);
void
truncate_cfg(struct ubpf_vm* vm, struct ubpf_basic_block* bb, uint32_t index, uint32_t target_pc);
void
instrument_slh(const struct ubpf_vm* vm, struct ubpf_basic_block* bb, struct ebpf_inst* insts);

#endif /* UBPF_SLH_H */
