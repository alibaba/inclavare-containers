/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CRYPTO_WRAPPER_H
#define _INTERNAL_CRYPTO_WRAPPER_H

#include <enclave-tls/crypto_wrapper.h>
#include "internal/core.h"

#define CRYPTO_WRAPPERS_DIR "/opt/enclave-tls/lib/crypto-wrappers/"

extern enclave_tls_err_t etls_crypto_wrapper_load_all(void);
extern enclave_tls_err_t etls_crypto_wrapper_load_single(const char *);
extern enclave_tls_err_t etls_crypto_wrapper_select(etls_core_context_t *, const char *);

extern crypto_wrapper_ctx_t *crypto_wrappers_ctx[CRYPTO_WRAPPER_TYPE_MAX];
extern crypto_wrapper_opts_t *crypto_wrappers_opts[CRYPTO_WRAPPER_TYPE_MAX];
extern unsigned int crypto_wrappers_nums;
extern unsigned registerd_crypto_wrapper_nums;

#endif