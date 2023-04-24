#ifndef UBPF_TYPESYSTEM_H
#define UBPF_TYPESYSTEM_H

#include "ubpf_int.h"
#include <stdint.h>

#define SOURCE 16
#define SINK 17
#define BASE_INDEX (SINK + 1)
#define COMP_NODE 16
#define INST_NODE_NUM (COMP_NODE + 1)

#define max(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })

#define min(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })

int
parse_basic_block(struct ubpf_vm* vm, struct ubpf_basic_block* bb);

int
check_basic_block_graph(struct ubpf_vm* vm);

struct ubpf_instruction_type
parse_instruction(struct ebpf_inst inst);

int
typecheck(struct ubpf_vm* vm);

void
ubpf_type_compose_instructions(
    struct ubpf_instruction_type* composed_type,
    struct ubpf_instruction_type* current_type,
    struct ubpf_instruction_type* next_type);

#define MAXN (1024 * INST_NODE_NUM)
#define MAXE 16384
extern const int UNREACHABLE;
extern int edge_num;

struct edge
{
    struct edge* next;
    int u, v, value;
};

int
dfs(struct ubpf_vm*, int node, int entry, int distance);
int
get_node(int pc, int reg);
void
add_edge(int u, int v, int dist);

int
to_pc(int node);

int
to_register(int node);

int
max_distance(int dist1, int dist2);

#endif
