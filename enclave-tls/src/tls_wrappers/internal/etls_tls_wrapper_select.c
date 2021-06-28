/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/tls_wrapper.h"

static enclave_tls_err_t init_tls_wrapper(tls_wrapper_ctx_t *tls_ctx)
{
	enclave_tls_err_t err = tls_ctx->opts->init(tls_ctx);

	if (err != TLS_WRAPPER_ERR_NONE)
		return err;

	if (!tls_ctx->tls_private)
		return -ENCLAVE_TLS_ERR_INIT;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_tls_wrapper_select(etls_core_context_t *ctx, const char *name)
{
	ETLS_DEBUG("selecting the tls wrapper '%s' ...\n", name);

	tls_wrapper_ctx_t *tls_ctx = NULL;
	for (unsigned int i = 0; i < registerd_tls_wrapper_nums; ++i) {
		if (name && strcmp(name, tls_wrappers_ctx[i]->opts->name))
			continue;

		tls_ctx = malloc(sizeof(*tls_ctx));
		if (!tls_ctx)
			return -ENCLAVE_TLS_ERR_NO_MEM;

		*tls_ctx = *tls_wrappers_ctx[i];

		/* Set necessary configurations from enclave_tls_init() to
		 * make init() working correctly.
		 */
		tls_ctx->conf_flags = ctx->config.flags;
		tls_ctx->enclave_id = ctx->config.enclave_id;
		tls_ctx->log_level = ctx->config.log_level;

		if (init_tls_wrapper(tls_ctx) == ENCLAVE_TLS_ERR_NONE)
			break;

		free(tls_ctx);
		tls_ctx = NULL;
	}

	if (!tls_ctx) {
		if (!name)
			ETLS_ERR("failed to select a tls wrapper\n");
		else
			ETLS_ERR("failed to select the tls wrapper '%s'\n", name);

		return -ENCLAVE_TLS_ERR_INIT;
	}

	ctx->tls_wrapper = tls_ctx;
	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_TLS_INITIALIZED;
	tls_ctx->etls_handle = ctx;

	ETLS_INFO("the tls wrapper '%s' selected\n", tls_ctx->opts->name);

	return ENCLAVE_TLS_ERR_NONE;
}
