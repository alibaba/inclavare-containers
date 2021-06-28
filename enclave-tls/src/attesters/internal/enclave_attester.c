/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/attester.h"

enclave_attester_opts_t *enclave_attesters_opts[ENCLAVE_ATTESTER_TYPE_MAX];
unsigned int registerd_enclave_attester_nums;

enclave_attester_ctx_t *enclave_attesters_ctx[ENCLAVE_ATTESTER_TYPE_MAX];
unsigned int enclave_attester_nums;
