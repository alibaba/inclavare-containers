/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>

#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"

tls_wrapper_err_t tls_wrapper_verify_certificate_extension(tls_wrapper_ctx_t *tls_ctx,
							   attestation_evidence_t *evidence,
							   uint8_t *hash, uint32_t hash_len)
{
	ETLS_DEBUG("tls_wrapper_verify_certificate_extension() called with evidence type: '%s'\n",
		   evidence->type);

	if (!tls_ctx || !tls_ctx->etls_handle || !tls_ctx->etls_handle->verifier ||
	    !tls_ctx->etls_handle->verifier->opts ||
	    !tls_ctx->etls_handle->verifier->opts->verify_evidence)
		return -TLS_WRAPPER_ERR_INVALID;

	if (strcmp(tls_ctx->etls_handle->verifier->opts->type, evidence->type) &&
	    !(tls_ctx->etls_handle->flags & ENCLAVE_TLS_CONF_VERIFIER_ENFORCED)) {
		ETLS_WARN("type doesn't match between verifier '%s' and evidence '%s'\n",
			  tls_ctx->etls_handle->verifier->opts->name, evidence->type);
		enclave_tls_err_t tlserr =
			etls_verifier_select(tls_ctx->etls_handle, evidence->type,
					     tls_ctx->etls_handle->config.cert_algo);
		if (tlserr != ENCLAVE_TLS_ERR_NONE) {
			ETLS_ERR("the verifier selecting err %#x during verifying cert extension\n",
				 tlserr);
			return -TLS_WRAPPER_ERR_INVALID;
		}
	}

	enclave_verifier_err_t err = tls_ctx->etls_handle->verifier->opts->verify_evidence(
		tls_ctx->etls_handle->verifier, evidence, hash, hash_len);
	if (err != ENCLAVE_VERIFIER_ERR_NONE) {
		ETLS_ERR("failed to verify evidence %#x\n", err);
		return -TLS_WRAPPER_ERR_INVALID;
	}

	return TLS_WRAPPER_ERR_NONE;
}
