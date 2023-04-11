#ifndef UBPF_TYPESYSTEM_H
#define UBPF_TYPESYSTEM_H

/* struct ubpf_basic_block_type { */
/*   int freshness[16]; */
/* }; */

#include "ubpf_int.h"
#include <stdint.h>

int
parse_basic_block(struct ubpf_vm* vm, struct ubpf_basic_block* bb);
int
parse_basic_block_graph(struct ubpf_vm* vm);
int
typecheck(struct ubpf_vm* vm);

#endif
