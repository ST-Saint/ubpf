#include "ubpf_typesystem.h"
#include "ebpf.h"
#include "ubpf_int.h"
#include "ubpf_slh.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint32_t mult_latency = 2;
const uint32_t mod_latency = 8;
const uint32_t div_latency = 12;
const uint32_t memory_load_latency = 20;
const uint32_t memory_store_latency = 32;

int
typecheck(struct ubpf_vm* vm)
{
    int ret = 0;
    printf("typecheck:\n");
    struct ubpf_cfg* cfg = vm->cfg;
    for (int i = 0; i < cfg->bb_num; ++i) {
        ret |= parse_basic_block(vm, cfg->bbq[i]);
    }
    if (ret) {
        return ret;
    }
    ret = parse_basic_block_graph(vm);
    return ret;
}

void
typeError(struct ubpf_vm* vm, uint32_t pc, uint32_t source_pc)
{
    struct ebpf_inst current_inst = ubpf_fetch_instruction(vm, pc);
    struct ebpf_inst source_inst = ubpf_fetch_instruction(vm, source_pc);
    fprintf(stdout, "\n");
    fprintf(stdout, "Type Error: stale register %s:\n", register_name(current_inst.src));
    fprintf(stdout, "instruction:\t");
    print_inst(&current_inst, pc);
    fprintf(stdout, "stale source:\t");
    print_inst(&source_inst, source_pc);
    fprintf(stdout, "\n");
}

int
parse_basic_block_graph(struct ubpf_vm* vm)
{
    struct ubpf_cfg* cfg = vm->cfg;
    for (int i = 0; i < cfg->bb_num; ++i) {
    }
    return 0;
}

int
parse_basic_block(struct ubpf_vm* vm, struct ubpf_basic_block* bb)
{
    int ret = 0;
    uint32_t num = bb->num_inst, pc;
    ubpf_basic_block_type* rolling;
    rolling = calloc(1, sizeof(ubpf_basic_block_type));
    /* staleness = calloc(16, sizeof(uint32_t)); */
    for (uint32_t i = 0; i < num; ++i) {
        pc = bb->base_index + i;
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, pc);
        memcpy(rolling, bb->type, sizeof(ubpf_basic_block_type));

        switch (inst.opcode) {
            // IMM: set staleness to 0
        case EBPF_OP_OR_IMM:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_SUB_IMM: {
            bb->type->staleness[inst.dst] = 0;
            bb->type->source[inst.dst] = pc;
            break;
        }

            // NOTE For the overlap problem:
            // consider the def-use graph, if a slow def instruction is followed by another def instruction
            // according to the sequnetial semantic, the def instruction is never used, so we can just overwrite it
            // the exception could be reg0 = op reg0
            // and it should also be considered as a compiler bug / developer introduced bug

            // MUL: set staleness to 2
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL64_IMM: {
            bb->type->staleness[inst.dst] = mult_latency;
            bb->type->source[inst.dst] = pc;
            break;
        }

        // DIV: set staleness to 6
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_DIV64_IMM: {
            bb->type->staleness[inst.dst] = div_latency;
            bb->type->source[inst.dst] = pc;
            break;
        }

        // MOD: set staleness 8
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_MOD64_IMM: {
            bb->type->staleness[inst.dst] = mod_latency;
            break;
        }

        // REG: set staleness to max_staleness(src, dst) + 1
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_REG:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_REG: {
            if (bb->type->staleness[inst.dst] < bb->type->staleness[inst.src]) {
                bb->type->staleness[inst.dst] = bb->type->staleness[inst.src];
                bb->type->source[inst.dst] = bb->type->source[inst.src];
            }
            ++bb->type->staleness[inst.dst];
            break;
        }

        case EBPF_OP_MUL_REG:
        case EBPF_OP_MUL64_REG:

        case EBPF_OP_DIV_REG:
        case EBPF_OP_DIV64_REG:

        // MOD: set staleness staleness + 8
        case EBPF_OP_MOD_REG:
        case EBPF_OP_MOD64_REG:

        // LE/BE: no inst.src, use inst.dst
        case EBPF_OP_LE:
        case EBPF_OP_BE:

        // MEMORY ACCESS:
        // Reg:
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW: {
            // Shall not use stale src register to load
            if (bb->type->staleness[inst.src] > 0) {
                uint32_t source_pc = bb->type->source[inst.src];
                typeError(vm, pc, source_pc);
                ret = -1;
            }
            if (bb->type->staleness[inst.dst] < bb->type->staleness[inst.src] + memory_load_latency) {
                bb->type->staleness[inst.dst] = bb->type->staleness[inst.src] + memory_load_latency;
                bb->type->source[inst.dst] = pc;
            }
            break;
        }
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW: {
            // Shall not use stale dst register to store
            if (bb->type->staleness[inst.dst] > 0) {
                uint32_t source_pc = bb->type->source[inst.dst];
                typeError(vm, pc, source_pc);
                ret = -1;
            }
            /* if (bb->type->staleness[inst.dst] < bb->type->staleness[inst.src] + memory_store_latency) { */
            /*     bb->type->staleness[inst.dst] = bb->type->staleness[inst.src] + memory_store_latency; */
            /*     bb->type->source[inst.dst] = pc; */
            /* } */
            break;
        }

        // IMMEDIATE
        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW: {
            if (bb->type->staleness[inst.dst] < memory_store_latency) {
                bb->type->staleness[inst.dst] = memory_store_latency;
                bb->type->source[inst.dst] = pc;
            }
            break;
        }
        case EBPF_OP_LDDW: {
            // reg[inst.dst] = u32(inst.imm) | ((uint64_t)ubpf_fetch_instruction(vm, pc++).imm << 32);
            ++i;
            printf("skip pc: %d\n", pc + 1);
            break;
        }

        // JIMM: check dst
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JGE_IMM: {
            if (bb->type->staleness[inst.src] > 0) {
                uint32_t source_pc = bb->type->source[inst.src];
                typeError(vm, pc, source_pc);
                ret = -1;
            }
        }

        // JREG: check src & dst
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JSLE32_REG:
        case EBPF_OP_JGE_REG: {
            if (bb->type->staleness[inst.src] > 0) {
                uint32_t source_pc = bb->type->source[inst.src];
                typeError(vm, pc, source_pc);
                ret = -1;
            }
            if (bb->type->staleness[inst.dst] > 0) {
                uint32_t source_pc = bb->type->source[inst.dst];
                typeError(vm, pc, source_pc);
                ret = -1;
            }
            break;
        }
        }

        for (uint32_t reg = 0; reg < 16; ++reg) {
            if (bb->type->staleness[reg] > 0) {
                bb->type->staleness[reg] = bb->type->staleness[reg] - 1;
            }
        }
    }
    return ret;
}
