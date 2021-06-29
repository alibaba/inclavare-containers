/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/attester.h"
#include "internal/core.h"

static enclave_tls_err_t init_enclave_attester(etls_core_context_t *ctx,
					       enclave_attester_ctx_t *attester_ctx,
					       enclave_tls_cert_algo_t algo)
{
        ETLS_DEBUG("init enclave attester etls_core_context: %#x\n", ctx);

	enclave_attester_err_t err = attester_ctx->opts->init(attester_ctx, algo);

	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		return -ENCLAVE_TLS_ERR_INIT;

	if (!attester_ctx->attester_private)
		return -ENCLAVE_TLS_ERR_INIT;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_attester_select(etls_core_context_t *ctx, const char *name,
				       enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("selecting the enclave attester '%s' ...\n", name);

	/* Explicitly specify the enclave verifier which will never be changed */
	if (name)
		ctx->flags |= ENCLAVE_TLS_CONF_VERIFIER_ENFORCED;

	enclave_attester_ctx_t *attester_ctx = NULL;
	for (unsigned int i = 0; i < registerd_enclave_attester_nums; ++i) {
		if (name && strcmp(name, enclave_attesters_ctx[i]->opts->name))
			continue;

		attester_ctx = malloc(sizeof(*attester_ctx));
		if (!attester_ctx)
			return -ENCLAVE_TLS_ERR_NO_MEM;

		memcpy(attester_ctx, enclave_attesters_ctx[i], sizeof(*attester_ctx));

		/* Set necessary configurations from enclave_tls_init() to
		 * make init() working correctly.
		 */
		attester_ctx->enclave_id = ctx->config.enclave_id;
		attester_ctx->log_level = ctx->config.log_level;

		if (init_enclave_attester(ctx, attester_ctx, algo) == ENCLAVE_TLS_ERR_NONE)
			break;

		free(attester_ctx);
		attester_ctx = NULL;
	}

	if (!attester_ctx) {
		if (!name)
			ETLS_ERR("failed to select an enclave attester\n");
		else
			ETLS_ERR("failed to select the enclave attester '%s'\n", name);

		return -ENCLAVE_TLS_ERR_INVALID;
	}

	ctx->attester = attester_ctx;
	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_QUOTING_INITIALIZED;

	ETLS_INFO("the enclave attester '%s' selected\n", ctx->attester->opts->name);

	return ENCLAVE_TLS_ERR_NONE;
}
