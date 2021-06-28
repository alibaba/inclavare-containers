/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>

crypto_wrapper_err_t wolfcrypt_pre_init(void)
{
	ETLS_DEBUG("called\n");

	return CRYPTO_WRAPPER_ERR_NONE;
}