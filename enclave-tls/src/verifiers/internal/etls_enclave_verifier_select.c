/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/verifier.h"
#include "internal/core.h"

static enclave_tls_err_t init_enclave_verifier(etls_core_context_t *ctx,
					       enclave_verifier_ctx_t *verifier_ctx,
					       enclave_tls_cert_algo_t algo)
{
        ETLS_DEBUG("init enclave verifier etls_core_context: %#x\n", ctx);

	enclave_verifier_err_t err = verifier_ctx->opts->init(verifier_ctx, algo);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		return -ENCLAVE_TLS_ERR_INIT;

	if (!verifier_ctx->verifier_private)
		return -ENCLAVE_TLS_ERR_INIT;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_verifier_select(etls_core_context_t *ctx, const char *name,
				       enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("selecting the enclave verifier '%s' ...\n", name);

	enclave_verifier_ctx_t *verifier_ctx = NULL;
	for (unsigned int i = 0; i < registerd_enclave_verifier_nums; ++i) {
		if (name && strcmp(name, enclave_verifiers_ctx[i]->opts->name))
			continue;

		verifier_ctx = malloc(sizeof(*verifier_ctx));
		if (!verifier_ctx)
			return -ENCLAVE_TLS_ERR_NO_MEM;

		memcpy(verifier_ctx, enclave_verifiers_ctx[i], sizeof(*verifier_ctx));

		/* Set necessary configurations from enclave_tls_init() to
		 * make init() working correctly.
		 */
		verifier_ctx->enclave_id = ctx->config.enclave_id;
		verifier_ctx->log_level = ctx->config.log_level;

		if (init_enclave_verifier(ctx, verifier_ctx, algo) == ENCLAVE_TLS_ERR_NONE)
			break;

		free(verifier_ctx);
		verifier_ctx = NULL;
	}

	if (!verifier_ctx) {
		if (!name)
			ETLS_ERR("failed to select an enclave verifier\n");
		else
			ETLS_ERR("failed to select the enclave verifier '%s'\n", name);

		return -ENCLAVE_TLS_ERR_INVALID;
	}

	ctx->verifier = verifier_ctx;

	ETLS_INFO("the enclave verifier '%s' selected\n", ctx->verifier->opts->name);

	return ENCLAVE_TLS_ERR_NONE;
}
