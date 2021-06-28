/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>

enclave_verifier_err_t sgx_la_verifier_pre_init(void)
{
	ETLS_DEBUG("called\n");

	return ENCLAVE_VERIFIER_ERR_NONE;
}
