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

int edges[MAXN][MAXN];
int edge_entry[MAXN], edge_num = 0;
struct edge edge[MAXE];
int dist[MAXN][MAXN];

const int UNREACHABLE = (int)(-(1 << 30));

void
init_edge(struct ubpf_vm* vm)
{
    memset(edge, -1, sizeof(edge));
    int node_num = (vm->num_insts + 1) * INST_NODE_NUM + BASE_INDEX;
    for (int i = 0; i < node_num; ++i) {
        for (int j = 0; j < node_num; ++j)
            if (i == j) {
                edges[i][j] = 0;
            } else {
                edges[i][j] = UNREACHABLE;
            }
    }
    for (int i = RAX; i <= R15; ++i) {
        int r = get_node(0, i);
        add_edge(SOURCE, r, 0);
    }
}

int
typecheck(struct ubpf_vm* vm)
{
    int ret = 0;
    printf("typecheck:\n");
    init_edge(vm);
    struct ubpf_cfg* cfg = vm->cfg;
    for (int i = 0; i < cfg->bb_num; ++i) {
        ret |= parse_basic_block(vm, cfg->bbq[i]);
    }
    if (ret) {
        return ret;
    }
    ret = check_basic_block_graph(vm);
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

/* int */
/* dfs(struct ubpf_vm* vm, int node, int entry, int distance) */
/* { */
/*     int pc = to_pc(node); */
/*     int reg = to_register(node); */

/*     int find = 0; */
/*     int next = 0; */
/*     if (reg == COMP_NODE) { */
/*         // Application */
/*         for (int i = RAX; i <= R15; ++i) { */
/*             next = get_node(pc + 1, i); */
/*             if (edges[node][next] != UNREACHABLE && dist[next][next] > 0) { */
/*                 if (find) { */
/*                     return 1; */
/*                 } */
/*             } */
/*         } */
/*     } */
/*     return 0; */
/* } */

int
check_loop(struct ubpf_vm* vm)
{
    printf("check_loop\n");
    int node_num = (vm->num_insts + 1) * INST_NODE_NUM + BASE_INDEX;
    int ret = 0, source = 0;
    for (int i = BASE_INDEX; i < node_num; ++i) {
        if (dist[i][i] > 0) {
            ret = 1;
            source = i;
            break;
        }
    }
    if (source != 0) {
        printf("Type error: speculative loop %d\n", source);
        /* return dfs(vm, source); */
        int pc = 0, reg = 0, out = 0;
        while (!out) {
            pc = to_pc(source);
            reg = to_register(source);
            struct ebpf_inst inst = ubpf_fetch_instruction(vm, pc);
            switch (inst.opcode) {
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
                print_inst(&inst, pc);
                out = 1;
                break;
            }
            if (out) {
                break;
            }
            int node;

            printf("reg %s\n", register_name(reg));
            if (reg == COMP_NODE) {
                // Application
                int find = 0;
                for (int i = RAX; i <= R15; ++i) {
                    node = get_node(pc + 1, i);
                    if (edges[source][node] != UNREACHABLE && dist[node][node] > 0) {
                        print_inst(&inst, pc);
                        source = node;
                        find = 1;
                        break;
                    }
                }
                if (find) {
                    continue;
                }
            } else {
                // Regular register
                // fallthrough
                node = get_node(pc + 1, reg);
                if (edges[source][node] != UNREACHABLE && dist[node][node] > 0) {
                    source = node;
                    continue;
                }
                // register usage
                node = get_node(pc, COMP_NODE);
                if (edges[source][node] != UNREACHABLE && dist[node][node] > 0) {
                    source = node;
                    continue;
                }
            }
            break;
        }
    }
    return ret;
}

int
check_control_data_flow(struct ubpf_vm* vm)
{
    int node_num = (vm->num_insts + 1) * INST_NODE_NUM + BASE_INDEX;
    if (dist[SOURCE][SINK] > 0) {
        /* printf("source sink: %d\n", dist[SOURCE][SINK]); */
        printf("Type error: specluative jmp/ld/st\n");
        int src = SOURCE, pc = -1;
        for (int i = BASE_INDEX; i < node_num; ++i) {
            if (dist[src][i] + dist[i][SINK] == dist[src][SINK]) {
                if (to_pc(i) != pc) {
                    pc = to_pc(i);
                    struct ebpf_inst inst = ubpf_fetch_instruction(vm, pc);
                    print_inst(&inst, pc);
                }
                src = i;
                /* printf("source i: %d %d %d %d\n", to_pc(i), to_register(i), dist[SOURCE][i], dist[i][SINK]); */
            }
        }
        printf("\n\n");
        return 1;
    }
    return 0;
}

int
check_basic_block_graph(struct ubpf_vm* vm)
{
    int node_num = (vm->num_insts + 1) * INST_NODE_NUM + BASE_INDEX;
    for (int i = 0; i < node_num; ++i) {
        for (int j = 0; j < node_num; ++j) {
            dist[i][j] = edges[i][j];
        }
    }
    for (int k = 0; k < node_num; ++k) {
        for (int i = 0; i < node_num; ++i) {
            for (int j = 0; j < node_num; ++j) {
                if (dist[i][k] == UNREACHABLE || dist[k][j] == UNREACHABLE) {
                    continue;
                }
                int distance = dist[i][k] + dist[k][j];
                if (distance > dist[i][j]) {
                    dist[i][j] = distance;
                }
            }
        }
    }
    int ret = 0;
    ret |= check_loop(vm);
    if (!ret) {
        ret |= check_control_data_flow(vm);
    }
    return ret;
}

void
print_type(struct ubpf_instruction_type* type)
{
    for (int i = 0; i < TYPE_DIMENSION; ++i) {
        for (int j = 0; j < TYPE_DIMENSION; ++j) {
            if (type->dist[i][j] == UNREACHABLE) {
                printf("NA\t");
            } else {
                printf("%d\t", type->dist[i][j]);
            }
        }
        printf("\n");
    }
    printf("\n");
}

void
print_path(struct ubpf_vm* vm, struct ubpf_basic_block* bb)
{
    int S = SOURCE, T = SINK, dist = bb->type[bb->num_inst - 1].dist[S][T];
    for (int i = bb->num_inst - 1; i >= 0; --i) {
        struct ebpf_inst inst = ubpf_fetch_instruction(vm, bb->base_index + i);
        struct ubpf_instruction_type type = parse_instruction(inst);
        for (int j = 0; j < TYPE_DIMENSION; ++j) {
            if (bb->type[i - 1].dist[S][j] + type.dist[j][T] == dist) {

                if (j == T && type.dist[j][T] == -1) {
                    // fallthrough
                } else {
                    /* printf("id: %d %d, reg: %s\n", i, j, register_name(j)); */
                    print_inst(&inst, bb->base_index + i);
                }
                T = j;
                dist = bb->type[i - 1].dist[S][j];
                break;
            }
        }
        if (S == T) {
            break;
        }
    }
    printf("\n");
}

struct ubpf_instruction_type
parse_instruction(struct ebpf_inst inst)
{
    struct ubpf_instruction_type type;
    for (int i = 0; i < TYPE_DIMENSION; ++i) {
        for (int j = 0; j < TYPE_DIMENSION; ++j) {
            type.dist[i][j] = UNREACHABLE;
        }
        type.dist[i][i] = -1;
    }
    type.dist[SOURCE][SOURCE] = type.dist[SINK][SINK] = 0;
    /* for (int reg = RAX; reg <= R15; ++reg) { */
    /*     type.source[reg] = UNREACHABLE; */
    /*     type.sink[reg] = UNREACHABLE; */
    /*     type.st_dist = UNREACHABLE; */
    /*     type.reg = -1; */
    /* } */
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
        type.dist[inst.dst][inst.dst] = 0;
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
        break;
    }

    // DIV: set staleness to 6
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV64_IMM: {
        break;
    }

    // MOD: set staleness 8
    case EBPF_OP_MOD_IMM:
    case EBPF_OP_MOD64_IMM: {
        break;
    }

    // LE/BE: no inst.src, use inst.dst
    case EBPF_OP_LE:
    case EBPF_OP_BE:

    // REG: set staleness to max_staleness(src, dst) + 1
    case EBPF_OP_ADD_REG:
    case EBPF_OP_SUB_REG:
    case EBPF_OP_OR_REG:
    case EBPF_OP_AND_REG:
    case EBPF_OP_LSH_REG:
    case EBPF_OP_RSH_REG:
    case EBPF_OP_NEG:
    case EBPF_OP_XOR_REG:
    case EBPF_OP_ARSH_REG:
    case EBPF_OP_ADD64_REG:
    case EBPF_OP_SUB64_REG:
    case EBPF_OP_OR64_REG:
    case EBPF_OP_AND64_REG:
    case EBPF_OP_LSH64_REG:
    case EBPF_OP_RSH64_REG:
    case EBPF_OP_NEG64:
    case EBPF_OP_XOR64_REG:
    case EBPF_OP_ARSH64_REG: {
        type.dist[inst.src][inst.dst] = 0;
        type.dist[inst.dst][inst.dst] = 0;
        break;
    }

    case EBPF_OP_MOV_REG:
    case EBPF_OP_MOV64_REG: {
        type.dist[inst.dst][inst.dst] = UNREACHABLE;
        type.dist[inst.src][inst.dst] = 0;
        break;
    }

    case EBPF_OP_MUL_REG:
    case EBPF_OP_MUL64_REG: {
        type.dist[inst.src][inst.dst] = mult_latency;
        type.dist[inst.dst][inst.dst] = mult_latency;
        type.dist[SOURCE][inst.dst] = mult_latency;
        break;
    }

    case EBPF_OP_DIV_REG:
    case EBPF_OP_DIV64_REG: {
        type.dist[inst.src][inst.dst] = div_latency;
        type.dist[inst.dst][inst.dst] = div_latency;
        type.dist[SOURCE][inst.dst] = div_latency;
        break;
    }
    // MOD: set staleness staleness + 8
    case EBPF_OP_MOD_REG:
    case EBPF_OP_MOD64_REG: {
        type.dist[inst.src][inst.dst] = mod_latency;
        type.dist[inst.dst][inst.dst] = mod_latency;
        type.dist[SOURCE][inst.dst] = mod_latency;
        break;
    }
    // MEMORY ACCESS:
    // Reg:
    case EBPF_OP_LDXW:
    case EBPF_OP_LDXH:
    case EBPF_OP_LDXB:
    case EBPF_OP_LDXDW: {
        type.dist[inst.dst][inst.dst] = UNREACHABLE;
        type.dist[inst.src][inst.dst] = memory_load_latency;
        type.dist[SOURCE][inst.dst] = memory_load_latency;
        type.dist[inst.src][SINK] = 0;
        break;
    }
    case EBPF_OP_STXW:
    case EBPF_OP_STXH:
    case EBPF_OP_STXB:
    case EBPF_OP_STXDW: {
        break;
    }

    // IMMEDIATE
    case EBPF_OP_STW:
    case EBPF_OP_STH:
    case EBPF_OP_STB:
    case EBPF_OP_STDW: {
        break;
    }
    case EBPF_OP_LDDW: {
        type.dist[inst.dst][inst.dst] = 0;
        break;
    }

    case EBPF_OP_JA: {
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
        type.dist[inst.dst][SINK] = 0;
        break;
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
        type.dist[inst.dst][SINK] = 0;
        type.dist[inst.src][SINK] = 0;
        type.sink[inst.dst] = 0;
        type.sink[inst.src] = 0;
        break;
    }
    }

    return type;
}

void
ubpf_type_compose_instructions(
    struct ubpf_instruction_type* composed_type,
    struct ubpf_instruction_type* current_type,
    struct ubpf_instruction_type* next_type)
{
    for (int i = 0; i < TYPE_DIMENSION; ++i) {
        for (int j = 0; j < TYPE_DIMENSION; ++j) {
            composed_type->dist[i][j] = UNREACHABLE;
        }
    }
    for (int i = 0; i < TYPE_DIMENSION; ++i) {
        for (int j = 0; j < TYPE_DIMENSION; ++j) {
            for (int k = 0; k < TYPE_DIMENSION; ++k) {
                if (current_type->dist[i][k] != UNREACHABLE && next_type->dist[k][j] != UNREACHABLE) {
                    composed_type->dist[i][j] =
                        max_distance(composed_type->dist[i][j], current_type->dist[i][k] + next_type->dist[k][j]);
                }
            }
        }
    }
}

int
parse_basic_block(struct ubpf_vm* vm, struct ubpf_basic_block* bb)
{
    uint32_t num = bb->num_inst, pc;
    struct ebpf_inst inst = ubpf_fetch_instruction(vm, bb->base_index);
    struct ubpf_instruction_type type;
    type = parse_instruction(inst);
    memcpy(bb->type + 0, &type, sizeof(struct ubpf_instruction_type));
    /* staleness = calloc(16, sizeof(uint32_t)); */
    for (uint32_t i = 1; i < num; ++i) {
        pc = bb->base_index + i;
        inst = ubpf_fetch_instruction(vm, pc);
        type = parse_instruction(inst);
        ubpf_type_compose_instructions(bb->type + i, bb->type + i - 1, &type);
        printf("index: %d:\n", i);
        print_type(bb->type + i);
        if (inst.opcode == EBPF_OP_LDXDW) {
            memcpy(bb->type + i + 1, bb->type + i, sizeof(struct ubpf_instruction_type));
            ++i;
        }
    }
    printf("index: %d:\n", bb->base_index);
    print_type(bb->type + bb->num_inst - 1);
    if (bb->type[bb->num_inst - 1].dist[SOURCE][SINK] > 0) {
        printf("type error: %d %d\n", bb->base_index, bb->type[bb->num_inst - 1].dist[SOURCE][SINK]);
        print_path(vm, bb);
        return 1;
    }
    return 0;
}

int
get_node(int pc, int reg)
{
    return pc * INST_NODE_NUM + reg + BASE_INDEX;
}

void
add_edge(int u, int v, int dist)
{
    int idx = edge_num;
    edge[idx].u = u, edge[idx].v = v, edge[idx].value = dist;
    edge[idx].next = &edge[edge_entry[u]];
    edge_entry[u] = idx;
    /* edges[u][v] = dist; */
}

int
to_pc(int node)
{
    return (node - BASE_INDEX - to_register(node)) / INST_NODE_NUM;
}

int
to_register(int node)
{
    return (node - BASE_INDEX) % INST_NODE_NUM;
}

int
max_distance(int dist1, int dist2)
{
    if (dist1 == UNREACHABLE && dist2 == UNREACHABLE) {
        return UNREACHABLE;
    } else if (dist1 != UNREACHABLE) {
        return dist1;
    } else if (dist2 != UNREACHABLE) {
        return dist2;
    } else {
        return max(dist1, dist2);
    }
}
