/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/api.h>
#include <enclave-tls/log.h>
#include "internal/core.h"

enclave_tls_err_t enclave_tls_negotiate(enclave_tls_handle handle, int fd)
{
	etls_core_context_t *ctx = (etls_core_context_t *)handle;

	ETLS_DEBUG("handle %p, fd %d\n", ctx, fd);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts ||
	    !ctx->tls_wrapper->opts->negotiate || fd < 0)
		return -ENCLAVE_TLS_ERR_INVALID;

	/* Check whether requiring to generate TLS certificate */
	if ((ctx->config.flags & ENCLAVE_TLS_CONF_FLAGS_SERVER) ||
	    (ctx->config.flags & ENCLAVE_TLS_CONF_FLAGS_MUTUAL)) {
		enclave_tls_err_t err = etls_core_generate_certificate(ctx);

		if (err != ENCLAVE_TLS_ERR_NONE)
			return err;
	}

	tls_wrapper_err_t t_err = ctx->tls_wrapper->opts->negotiate(ctx->tls_wrapper, fd);
	if (t_err != TLS_WRAPPER_ERR_NONE)
		return t_err;

	ctx->tls_wrapper->fd = fd;

	return ENCLAVE_TLS_ERR_NONE;
}
