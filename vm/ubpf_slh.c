#include "ebpf.h"
#include "ubpf_int.h"
#include "ubpf_jit_x86_64.h"
#include "ubpf_slh.h"
#include "ubpf_typesystem.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
BB   (R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15)
  -> (R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15)
*/

void
init_bb(struct ubpf_basic_block* bb)
{
    bb->base_index = bb->num_inst = 0;
    bb->insts = NULL;
    /* bb->type = calloc(1, sizeof(ubpf_basic_block_type)); */
    /* for (int reg = 0; reg < 16; ++reg) { */
    /*     bb->type.source[reg] = UNREACHABLE; */
    /*     bb->type.sink[reg] = UNREACHABLE; */
    /*     bb->type.st_dist = UNREACHABLE; */
    /*     bb->type.reg = -1; */
    /* } */
    bb->fallthrough = bb->jump = NULL;
}

// REVIEW unconditional jump don't have fallthrough BB
void
truncate_cfg(struct ubpf_vm* vm, struct ubpf_basic_block* bb, uint32_t index, uint32_t target_pc)
{
    struct ubpf_cfg* cfg = vm->cfg;
    struct ubpf_basic_block *jump_bb, *fallthrough_bb;

    if (cfg->maps[index + 1] == NULL) {
        fallthrough_bb = malloc(sizeof(struct ubpf_basic_block));
        init_bb(fallthrough_bb);

        fallthrough_bb->base_index = index + 1;
        fallthrough_bb->insts = &vm->insts[index + 1];
        cfg->maps[index + 1] = fallthrough_bb;
        bb->fallthrough = fallthrough_bb;
    } else {
        fallthrough_bb = cfg->maps[index + 1];
    }
    if (cfg->maps[target_pc] == NULL) {
        jump_bb = malloc(sizeof(struct ubpf_basic_block));
        init_bb(jump_bb);
        jump_bb->insts = &vm->insts[target_pc];
        jump_bb->base_index = target_pc;
        cfg->maps[target_pc] = jump_bb;
    } else {
        jump_bb = cfg->maps[target_pc];
    }

    bb->jump = jump_bb;
    bb->fallthrough = fallthrough_bb;
}

int
parse_ebpf_inst(struct ubpf_vm* vm)
{
    /* struct ebpf_inst *inst = NULL; */
    vm->cfg = calloc(1, sizeof(struct ubpf_cfg));

    struct ubpf_cfg* cfg = vm->cfg;
    struct ubpf_basic_block* bb;
    uint32_t target_pc;

    memset(cfg->maps, 0, sizeof(cfg->maps));

    bb = malloc(sizeof(struct ubpf_basic_block));
    init_bb(bb);
    cfg->entry = bb;
    cfg->maps[0] = bb;
    for (int i = 0; i < vm->num_insts; ++i) {
        /* inst = &vm->insts[i]; */
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, i);
        bb = cfg->maps[i];
        bb->num_inst += 1;
        if (bb->base_index == i) {
            cfg->bbq[cfg->bb_num] = bb;
            ++cfg->bb_num;
        }

        switch (inst.opcode) {
        /* BPF_JA
           0x00
           PC += off
           BPF_JMP only */
        case EBPF_OP_JA:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JSLE32_REG:
            /* fprintf( */
            /*     stdout, */
            /*     "index: %d EBPF_OP_JSGT_REG src: %d, dst %d, offset: %d, imm: %d, target_pc: %d\n", */
            /*     i, */
            /*     inst.dst, */
            /*     inst.src, */
            /*     inst.offset, */
            /*     inst.imm, */
            /*     i + inst.offset + 1); */
            target_pc = i + inst.offset + 1;
            truncate_cfg(vm, bb, i, target_pc);
            break;
        case EBPF_OP_LDDW: {
            // LDDW skip next instruction
            ++bb->num_inst;
            ++i;
        }
        default:
            if (i + 1 < vm->num_insts) {
                if (cfg->maps[i + 1] == NULL) {
                    cfg->maps[i + 1] = bb;
                } else {
                    bb->fallthrough = cfg->maps[i + 1];
                }
            }
            break;
        }
    }
    print_vm_insts(vm);
    print_cfg(cfg);
    return typecheck(vm);
}

void
print_vm_insts(struct ubpf_vm* vm)
{
    // check register usage
    for (int i = 0; i < vm->num_insts; ++i) {
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, i);
        print_inst(&inst, i);
        if (inst.opcode == EBPF_OP_LDDW)
            ++i;
    }
}

void
print_inst(struct ebpf_inst* inst, uint32_t pc)
{
    // check register usage

    fprintf(
        stdout,
        "Instruction:\t%d,\t%*s,\tsrc reg: %s,\tdst reg: %s\toff:\t%d\timm: %d\n",
        pc,
        20,
        instruct_opname(inst->opcode),
        register_name(inst->src),
        register_name(inst->dst),
        inst->offset,
        inst->imm);
}

void
print_cfg(struct ubpf_cfg* cfg)
{
    fprintf(stdout, "test instrument done\n");

    char* filename = "ubpf_cfg.dot";
    FILE* fp;
    // Open the file for writing in binary mode
    fp = fopen(filename, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }
    char header[64] = "digraph ubpf_cfg {\n\tnode [shape=square];\n";
    char footer[32] = "\n}";
    char buffer[128] = {};
    fwrite(header, sizeof(char), strlen(header), fp);
    for (int i = 0; i < cfg->bb_num; ++i) {
        struct ubpf_basic_block *bb = cfg->bbq[i], *fallthrough, *jump;

        fallthrough = bb->fallthrough;
        jump = bb->jump;
        if (fallthrough != NULL) {
            sprintf(
                buffer,
                "\t\"[%d:%d)\" -> \"[%d:%d)\" [label=\"fallthrough\"];\n",
                bb->base_index,
                bb->base_index + bb->num_inst,
                fallthrough->base_index,
                fallthrough->base_index + fallthrough->num_inst);
            fwrite(buffer, sizeof(char), strlen(buffer), fp);
        }
        if (jump != NULL) {
            sprintf(
                buffer,
                "\t\"[%d:%d)\" -> \"[%d:%d)\" [label=\"jump\"];\n",
                bb->base_index,
                bb->base_index + bb->num_inst,
                jump->base_index,
                jump->base_index + jump->num_inst);
            fwrite(buffer, sizeof(char), strlen(buffer), fp);
        }
    }
    fwrite(footer, sizeof(char), strlen(footer), fp);
}

/* void */
/* instrument_slh(const struct ubpf_vm* vm, struct ubpf_basic_block* bb, struct ebpf_inst* insts) */
/* { */
/* } */

char*
instruct_opname(uint8_t opcode)
{
    switch (opcode) {
    case EBPF_OP_ADD_IMM:
        return "EBPF_OP_ADD_IMM";
    case EBPF_OP_ADD_REG:
        return "EBPF_OP_ADD_REG";
    case EBPF_OP_SUB_IMM:
        return "EBPF_OP_SUB_IMM";
    case EBPF_OP_SUB_REG:
        return "EBPF_OP_SUB_REG";
    case EBPF_OP_MUL_IMM:
        return "EBPF_OP_MUL_IMM";
    case EBPF_OP_MUL_REG:
        return "EBPF_OP_MUL_REG";
    case EBPF_OP_DIV_IMM:
        return "EBPF_OP_DIV_IMM";
    case EBPF_OP_DIV_REG:
        return "EBPF_OP_DIV_REG";
    case EBPF_OP_OR_IMM:
        return "EBPF_OP_OR_IMM";
    case EBPF_OP_OR_REG:
        return "EBPF_OP_OR_REG";
    case EBPF_OP_AND_IMM:
        return "EBPF_OP_AND_IMM";
    case EBPF_OP_AND_REG:
        return "EBPF_OP_AND_REG";
    case EBPF_OP_LSH_IMM:
        return "EBPF_OP_LSH_IMM";
    case EBPF_OP_LSH_REG:
        return "EBPF_OP_LSH_REG";
    case EBPF_OP_RSH_IMM:
        return "EBPF_OP_RSH_IMM";
    case EBPF_OP_RSH_REG:
        return "EBPF_OP_RSH_REG";
    case EBPF_OP_NEG:
        return "EBPF_OP_NEG";
    case EBPF_OP_MOD_IMM:
        return "EBPF_OP_MOD_IMM";
    case EBPF_OP_MOD_REG:
        return "EBPF_OP_MOD_REG";
    case EBPF_OP_XOR_IMM:
        return "EBPF_OP_XOR_IMM";
    case EBPF_OP_XOR_REG:
        return "EBPF_OP_XOR_REG";
    case EBPF_OP_MOV_IMM:
        return "EBPF_OP_MOV_IMM";
    case EBPF_OP_MOV_REG:
        return "EBPF_OP_MOV_REG";
    case EBPF_OP_ARSH_IMM:
        return "EBPF_OP_ARSH_IMM";
    case EBPF_OP_ARSH_REG:
        return "EBPF_OP_ARSH_REG";
    case EBPF_OP_LE:
        return "EBPF_OP_LE";
    case EBPF_OP_BE:
        return "EBPF_OP_BE";
    case EBPF_OP_ADD64_IMM:
        return "EBPF_OP_ADD64_IMM";
    case EBPF_OP_ADD64_REG:
        return "EBPF_OP_ADD64_REG";
    case EBPF_OP_SUB64_IMM:
        return "EBPF_OP_SUB64_IMM";
    case EBPF_OP_SUB64_REG:
        return "EBPF_OP_SUB64_REG";
    case EBPF_OP_MUL64_IMM:
        return "EBPF_OP_MUL64_IMM";
    case EBPF_OP_MUL64_REG:
        return "EBPF_OP_MUL64_REG";
    case EBPF_OP_DIV64_IMM:
        return "EBPF_OP_DIV64_IMM";
    case EBPF_OP_DIV64_REG:
        return "EBPF_OP_DIV64_REG";
    case EBPF_OP_OR64_IMM:
        return "EBPF_OP_OR64_IMM";
    case EBPF_OP_OR64_REG:
        return "EBPF_OP_OR64_REG";
    case EBPF_OP_AND64_IMM:
        return "EBPF_OP_AND64_IMM";
    case EBPF_OP_AND64_REG:
        return "EBPF_OP_AND64_REG";
    case EBPF_OP_LSH64_IMM:
        return "EBPF_OP_LSH64_IMM";
    case EBPF_OP_LSH64_REG:
        return "EBPF_OP_LSH64_REG";
    case EBPF_OP_RSH64_IMM:
        return "EBPF_OP_RSH64_IMM";
    case EBPF_OP_RSH64_REG:
        return "EBPF_OP_RSH64_REG";
    case EBPF_OP_NEG64:
        return "EBPF_OP_NEG64";
    case EBPF_OP_MOD64_IMM:
        return "EBPF_OP_MOD64_IMM";
    case EBPF_OP_MOD64_REG:
        return "EBPF_OP_MOD64_REG";
    case EBPF_OP_XOR64_IMM:
        return "EBPF_OP_XOR64_IMM";
    case EBPF_OP_XOR64_REG:
        return "EBPF_OP_XOR64_REG";
    case EBPF_OP_MOV64_IMM:
        return "EBPF_OP_MOV64_IMM";
    case EBPF_OP_MOV64_REG:
        return "EBPF_OP_MOV64_REG";
    case EBPF_OP_ARSH64_IMM:
        return "EBPF_OP_ARSH64_IMM";
    case EBPF_OP_ARSH64_REG:
        return "EBPF_OP_ARSH64_REG";
    case EBPF_OP_LDXW:
        return "EBPF_OP_LDXW";
    case EBPF_OP_LDXH:
        return "EBPF_OP_LDXH";
    case EBPF_OP_LDXB:
        return "EBPF_OP_LDXB";
    case EBPF_OP_LDXDW:
        return "EBPF_OP_LDXDW";
    case EBPF_OP_STW:
        return "EBPF_OP_STW";
    case EBPF_OP_STH:
        return "EBPF_OP_STH";
    case EBPF_OP_STB:
        return "EBPF_OP_STB";
    case EBPF_OP_STDW:
        return "EBPF_OP_STDW";
    case EBPF_OP_STXW:
        return "EBPF_OP_STX";
    case EBPF_OP_STXH:
        return "EBPF_OP_STXH";
    case EBPF_OP_STXB:
        return "EBPF_OP_STX";
    case EBPF_OP_STXDW:
        return "EBPF_OP_STXDW";
    case EBPF_OP_LDDW:
        return "EBPF_OP_LDDW";
    case EBPF_MODE_JA:
        return "EBPF_MODE_JA";
    case EBPF_MODE_JEQ:
        return "EBPF_MODE_JE";
    case EBPF_MODE_JGT:
        return "EBPF_MODE_JGT";
    case EBPF_MODE_JGE:
        return "EBPF_MODE_JG";
    case EBPF_MODE_JSET:
        return "EBPF_MODE_JSET";
    case EBPF_MODE_JNE:
        return "EBPF_MODE_JN";
    case EBPF_MODE_JSGT:
        return "EBPF_MODE_JSGT";
    case EBPF_MODE_JSGE:
        return "EBPF_MODE_JSG";
    case EBPF_MODE_CALL:
        return "EBPF_MODE_CALL";
    case EBPF_MODE_EXIT:
        return "EBPF_MODE_EXI";
    case EBPF_MODE_JLT:
        return "EBPF_MODE_JLT";
    case EBPF_MODE_JLE:
        return "EBPF_MODE_JL";
    case EBPF_MODE_JSLT:
        return "EBPF_MODE_JSLT";
    case EBPF_MODE_JSLE:
        return "EBPF_MODE_JSL";
    case EBPF_OP_JA:
        return "EBPF_OP_JA";
    case EBPF_OP_JEQ_IMM:
        return "EBPF_OP_JEQ_IMM";
    case EBPF_OP_JEQ_REG:
        return "EBPF_OP_JEQ_REG";
    case EBPF_OP_JGT_IMM:
        return "EBPF_OP_JGT_IMM";
    case EBPF_OP_JGT_REG:
        return "EBPF_OP_JGT_REG";
    case EBPF_OP_JGE_IMM:
        return "EBPF_OP_JGE_IMM";
    case EBPF_OP_JGE_REG:
        return "EBPF_OP_JGE_REG";
    case EBPF_OP_JSET_REG:
        return "EBPF_OP_JSET_REG";
    case EBPF_OP_JSET_IMM:
        return "EBPF_OP_JSET_IMM";
    case EBPF_OP_JNE_IMM:
        return "EBPF_OP_JNE_IMM";
    case EBPF_OP_JNE_REG:
        return "EBPF_OP_JNE_REG";
    case EBPF_OP_JSGT_IMM:
        return "EBPF_OP_JSGT_IMM";
    case EBPF_OP_JSGT_REG:
        return "EBPF_OP_JSGT_REG";
    case EBPF_OP_JSGE_IMM:
        return "EBPF_OP_JSGE_IMM";
    case EBPF_OP_JSGE_REG:
        return "EBPF_OP_JSGE_REG";
    case EBPF_OP_CALL:
        return "EBPF_OP_CALL";
    case EBPF_OP_EXIT:
        return "EBPF_OP_EXIT";
    case EBPF_OP_JLT_IMM:
        return "EBPF_OP_JLT_IMM";
    case EBPF_OP_JLT_REG:
        return "EBPF_OP_JLT_REG";
    case EBPF_OP_JLE_IMM:
        return "EBPF_OP_JLE_IMM";
    case EBPF_OP_JLE_REG:
        return "EBPF_OP_JLE_REG";
    case EBPF_OP_JSLT_IMM:
        return "EBPF_OP_JSLT_IMM";
    case EBPF_OP_JSLT_REG:
        return "EBPF_OP_JSLT_REG";
    case EBPF_OP_JSLE_IMM:
        return "EBPF_OP_JSLE_IMM";
    case EBPF_OP_JSLE_REG:
        return "EBPF_OP_JSLE_REG";
    case EBPF_OP_JEQ32_IMM:
        return "EBPF_OP_JEQ32_IMM";
    case EBPF_OP_JEQ32_REG:
        return "EBPF_OP_JEQ32_REG";
    case EBPF_OP_JGT32_IMM:
        return "EBPF_OP_JGT32_IMM";
    case EBPF_OP_JGT32_REG:
        return "EBPF_OP_JGT32_REG";
    case EBPF_OP_JGE32_IMM:
        return "EBPF_OP_JGE32_IMM";
    case EBPF_OP_JGE32_REG:
        return "EBPF_OP_JGE32_REG";
    case EBPF_OP_JSET32_REG:
        return "EBPF_OP_JSET32_REG";
    case EBPF_OP_JSET32_IMM:
        return "EBPF_OP_JSET32_IMM";
    case EBPF_OP_JNE32_IMM:
        return "EBPF_OP_JNE32_IMM";
    case EBPF_OP_JNE32_REG:
        return "EBPF_OP_JNE32_REG";
    case EBPF_OP_JSGT32_IMM:
        return "EBPF_OP_JSGT32_IMM";
    case EBPF_OP_JSGT32_REG:
        return "EBPF_OP_JSGT32_REG";
    case EBPF_OP_JSGE32_IMM:
        return "EBPF_OP_JSGE32_IMM";
    case EBPF_OP_JSGE32_REG:
        return "EBPF_OP_JSGE32_REG";
    case EBPF_OP_JLT32_IMM:
        return "EBPF_OP_JLT32_IMM";
    case EBPF_OP_JLT32_REG:
        return "EBPF_OP_JLT32_REG";
    case EBPF_OP_JLE32_IMM:
        return "EBPF_OP_JLE32_IMM";
    case EBPF_OP_JLE32_REG:
        return "EBPF_OP_JLE32_REG";
    case EBPF_OP_JSLT32_IMM:
        return "EBPF_OP_JSLT32_IMM";
    case EBPF_OP_JSLT32_REG:
        return "EBPF_OP_JSLT32_REG";
    case EBPF_OP_JSLE32_IMM:
        return "EBPF_OP_JSLE32_IMM";
    case EBPF_OP_JSLE32_REG:
        return "EBPF_OP_JSLE32_REG";
    }
    return "";
}

char*
register_name(uint8_t reg)
{
    switch (reg) {
    case RAX: {
        return "RAX";
    }
    case RBX: {
        return "RBX";
    }
    case RCX: {
        return "RCX";
    }
    case RDX: {
        return "RDX";
    }
    case RSI: {
        return "RSI";
    }
    case RDI: {
        return "RDI";
    }
    case RBP: {
        return "RBP";
    }
    case RSP: {
        return "RSP";
    }
    case R8: {
        return "R8";
    }
    case R9: {
        return "R9";
    }
    case R10: {
        return "R10";
    }
    case R11: {
        return "R11";
    }
    case R12: {
        return "R12";
    }
    case R13: {
        return "R13";
    }
    case R14: {
        return "R14";
    }
    case R15: {
        return "R15";
    }
    default:
        return "";
    }
}
