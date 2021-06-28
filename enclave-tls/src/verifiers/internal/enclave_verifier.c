/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/verifier.h"

enclave_verifier_opts_t *enclave_verifiers_opts[ENCLAVE_VERIFIER_TYPE_MAX];
unsigned int registerd_enclave_verifier_nums;

enclave_verifier_ctx_t *enclave_verifiers_ctx[ENCLAVE_VERIFIER_TYPE_MAX];
unsigned int enclave_verifier_nums;
