#include "ubpf_typesystem.h"
#include "ubpf_int.h"
#include <stdint.h>
#include <stdlib.h>

void
parse_basic_block(struct ubpf_vm* vm, struct ubpf_basic_block* bb)
{
    uint32_t num = bb->num_inst;
    uint32_t base_index = bb->base_index;
    uint32_t(*freshness)[16] = bb->type, (*staleness)[16];
    staleness = calloc(16, sizeof(uint32_t));
    for (uint32_t i = 0; i < num; ++i) {
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, base_index + i);
        for (uint32_t reg = 0; reg < 16; ++reg) {
            *staleness[reg] = *freshness[reg];
        }
        switch (inst.opcode) {
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV64_IMM: {
            *freshness[inst.dst] = 0;
            break;
        }
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_MOD64_IMM:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_ADD_REG:
            *freshness[inst.dst] = *freshness[inst.src] + 1;
            break;
        }
        for (uint32_t reg = 0; reg < 16; ++reg) {
            *freshness[reg] = *staleness[reg];
        }
    }
    return;
}
