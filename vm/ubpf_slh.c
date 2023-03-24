#include "ebpf.h"
#include "ubpf_int.h"
#include "ubpf_slh.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
init_bb(struct ubpf_basic_block* bb)
{
    bb->index = bb->num_inst = 0;
    bb->insts = NULL;
    bb->fallthrough = bb->jump = NULL;
}

// FIXME unconditional jump don't have fallthrough BB
void
truncate_cfg(struct ubpf_vm* vm, struct ubpf_basic_block* bb, uint32_t index, uint32_t target_pc)
{
    struct ubpf_cfg* cfg = vm->cfg;
    struct ubpf_basic_block *jump_bb, *fallthrough_bb;

    if (cfg->maps[index + 1] == NULL) {
        fallthrough_bb = malloc(sizeof(struct ubpf_basic_block));
        init_bb(fallthrough_bb);

        fallthrough_bb->index = index + 1;
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
        jump_bb->index = target_pc;
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
    vm->cfg = malloc(sizeof(struct ubpf_cfg));

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
        switch (inst.opcode) {
        /* BPF_JA
           0x00
           PC += off
           BPF_JMP only */
        case EBPF_OP_JA: {
            fprintf(
                stdout,
                "index: %d EBPF_OP_JA src: %d, dst %d, offset: %d, imm: %d, target_pc: %d\n",
                i,
                inst.dst,
                inst.src,
                inst.offset,
                inst.imm,
                i + inst.offset + 1);
            target_pc = i + inst.offset + 1;
            truncate_cfg(vm, bb, i, target_pc);
            break;
        }
        case EBPF_OP_JEQ_IMM: {
            fprintf(
                stdout,
                "index: %d EBPF_OP_JEQ_IMM src: %d, dst %d, offset: %d, imm: %d, target_pc: %d\n",
                i,
                inst.dst,
                inst.src,
                inst.offset,
                inst.imm,
                i + inst.offset + 1);
            target_pc = i + inst.offset + 1;
            truncate_cfg(vm, bb, i, target_pc);
            break;
        }
        case EBPF_OP_JSGT_REG: {
            fprintf(
                stdout,
                "index: %d EBPF_OP_JSGT_REG src: %d, dst %d, offset: %d, imm: %d, target_pc: %d\n",
                i,
                inst.dst,
                inst.src,
                inst.offset,
                inst.imm,
                i + inst.offset + 1);
            target_pc = i + inst.offset + 1;
            truncate_cfg(vm, bb, i, target_pc);
            break;
        }
        default:
            if (i + 1 < vm->num_insts && cfg->maps[i + 1] == NULL) {
                cfg->maps[i + 1] = bb;
            }
            break;
        }
    }
    print_cfg(cfg->entry, 1);
    return 0;
}

void
print_cfg(struct ubpf_basic_block* bb, int depth)
{
    if (depth > 8) {
        return;
    }
    char indent[8 * depth + 1];
    for (int i = 0; i < 8 * depth; ++i) {
        indent[i] = ' ';
    }
    /* memset(indent, 32, sizeof(8 * depth)); */
    indent[8 * depth] = 0;
    fprintf(stdout, "%s|bb index: [%d, %d]\n", indent, bb->index, bb->index + bb->num_inst - 1);
    if (bb->jump != NULL) {
        print_cfg(bb->jump, depth + 1);
    }
    if (bb->fallthrough != NULL) {
        print_cfg(bb->fallthrough, depth);
    }
}

void
instrument_slh(const struct ubpf_vm* vm, struct ubpf_basic_block* bb, struct ebpf_inst* insts)
{
    fprintf(stdout, "test instrument %d\n", bb->num_inst);
    // check register usage
    for (int i = 0; i < bb->num_inst; ++i) {
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, bb->index + i);

        fprintf(
            stdout,
            "index: %d, op: %x, src reg: %s, dst reg: %s off: %d imm: %d\n",
            bb->index + i,
            inst.opcode,
            register_name(inst.src),
            register_name(inst.dst),
            inst.offset,
            inst.imm);

        insts[i] = inst;
    }
    fprintf(stdout, "test instrument done\n");
}

char*
register_name(uint32_t reg)
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
