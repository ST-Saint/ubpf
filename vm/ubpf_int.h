// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2022 Linaro Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include <stdint.h>
#include <ubpf.h>
#include "ebpf.h"

#define MAX_BASIC_BLOCK 1024
#define MAX_INSTRUCTIOSN 65536

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

#define TYPE_DIMENSION (17 + 1)

struct ubpf_spectre_type
{
    int32_t dist[TYPE_DIMENSION][TYPE_DIMENSION];
    int32_t source[16];
    int32_t sink[16];
    int32_t st_dist, reg;
};

struct ubpf_basic_block
{
    /* the index of the first instruction in ubpf_vm->ebpf_inst */
    uint32_t id;
    uint32_t base_index;
    uint32_t num_inst;
    struct ubpf_spectre_type* type;
    struct ubpf_spectre_type types[MAX_INSTRUCTIOSN];
    struct ebpf_inst* insts;
    struct ubpf_basic_block *fallthrough, *jump;
};

struct ubpf_cfg
{
    uint32_t bb_num;
    struct ubpf_basic_block *entry, *exit;
    struct ubpf_basic_block* maps[MAX_INSTRUCTIOSN];
    struct ubpf_basic_block* bbq[MAX_BASIC_BLOCK];
    struct ubpf_spectre_type path_type[MAX_BASIC_BLOCK];
};

struct ubpf_vm
{
    struct ebpf_inst* insts;
    struct ubpf_cfg* cfg;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
    ext_func* ext_funcs;
    const char** ext_func_names;
    bool bounds_check_enabled;
    int (*error_printf)(FILE* stream, const char* format, ...);
    int (*translate)(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
    int unwind_stack_extension_index;
    uint64_t pointer_secret;
    ubpf_data_relocation data_relocation_function;
    void* data_relocation_user_data;
    ubpf_bounds_check bounds_check_function;
    void* bounds_check_user_data;
#ifdef DEBUG
    uint64_t* regs;
#endif
};

/* The various JIT targets.  */
int
ubpf_translate_arm64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
int
ubpf_translate_x86_64(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
int
ubpf_translate_null(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);

char*
ubpf_error(const char* fmt, ...);
unsigned int
ubpf_lookup_registered_function(struct ubpf_vm* vm, const char* name);

/**
 * @brief Fetch the instruction at the given index.
 *
 * @param[in] vm The VM to fetch the instruction from.
 * @param[in] pc The index of the instruction to fetch.
 * @return The instruction.
 */
struct ebpf_inst
ubpf_fetch_instruction(const struct ubpf_vm* vm, uint16_t pc);

/**
 * @brief Store the given instruction at the given index.
 *
 * @param[in] vm The VM to store the instruction in.
 * @param[in] pc The index of the instruction to store.
 * @param[in] inst The instruction to store.
 */
void
ubpf_store_instruction(const struct ubpf_vm* vm, uint16_t pc, struct ebpf_inst inst);

#endif
