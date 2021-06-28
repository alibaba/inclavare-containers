/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_VERIFIER_H
#define _INTERNAL_VERIFIER_H

#include <enclave-tls/verifier.h>
#include "internal/core.h"

#define ENCLAVE_VERIFIERS_DIR "/opt/enclave-tls/lib/verifiers/"

extern enclave_tls_err_t etls_enclave_verifier_load_all(void);
extern enclave_tls_err_t etls_enclave_verifier_load_single(const char *);
extern enclave_tls_err_t etls_verifier_select(etls_core_context_t *, const char *,
					      enclave_tls_cert_algo_t);
extern enclave_verifier_opts_t *enclave_verifiers_opts[ENCLAVE_VERIFIER_TYPE_MAX];
extern enclave_verifier_ctx_t *enclave_verifiers_ctx[ENCLAVE_VERIFIER_TYPE_MAX];
extern unsigned int enclave_verifier_nums;
extern unsigned int registerd_enclave_verifier_nums;

#endif
