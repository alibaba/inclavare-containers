/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SGX_ECDSA_H
#define _SGX_ECDSA_H

#include <sgx_urts.h>

typedef struct {
	sgx_enclave_id_t eid;
} sgx_ecdsa_ctx_t;

#endif