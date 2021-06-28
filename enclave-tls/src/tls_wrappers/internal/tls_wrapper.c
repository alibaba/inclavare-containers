/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/tls_wrapper.h"

tls_wrapper_opts_t *tls_wrappers_opts[TLS_WRAPPER_TYPE_MAX];
unsigned int registerd_tls_wrapper_nums;

tls_wrapper_ctx_t *tls_wrappers_ctx[TLS_WRAPPER_TYPE_MAX];
unsigned int tls_wrappers_nums;
