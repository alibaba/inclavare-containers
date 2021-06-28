/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_ATTESTER_H
#define _INTERNAL_ATTESTER_H

#include <enclave-tls/attester.h>
#include "internal/core.h"

#define ENCLAVE_ATTESTERS_DIR "/opt/enclave-tls/lib/attesters/"

extern enclave_tls_err_t etls_enclave_attester_load_all(void);
extern enclave_tls_err_t etls_enclave_attester_load_single(const char *);
extern enclave_tls_err_t etls_attester_select(etls_core_context_t *, const char *,
					      enclave_tls_cert_algo_t);
extern enclave_attester_opts_t *enclave_attesters_opts[ENCLAVE_ATTESTER_TYPE_MAX];
extern enclave_attester_ctx_t *enclave_attesters_ctx[ENCLAVE_ATTESTER_TYPE_MAX];
extern unsigned int enclave_attester_nums;
extern unsigned int registerd_enclave_attester_nums;

#endif
