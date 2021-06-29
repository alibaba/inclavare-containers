/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include <internal/core.h>
#ifdef SGX
#include "etls_t.h"
#endif

tls_wrapper_err_t nulltls_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	ETLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	ssize_t rc;
	rc = etls_write(ctx->fd, buf, *buf_size);
	if (rc < 0) {
		ETLS_ERR("failed to transmit data %zu\n", rc);
		return TLS_WRAPPER_ERR_TRANSMIT;
	}

	*buf_size = (size_t)rc;

	return TLS_WRAPPER_ERR_NONE;
}
