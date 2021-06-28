/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>

enclave_attester_err_t nullattester_cleanup(enclave_attester_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
