/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_pre_init(void)
{
	ETLS_DEBUG("called\n");

	return TLS_WRAPPER_ERR_NONE;
}