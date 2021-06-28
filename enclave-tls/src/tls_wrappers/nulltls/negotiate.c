/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	ETLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!(ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER) ||
	    ((ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_MUTUAL) &&
	     (ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER))) {
		tls_wrapper_err_t err;
		uint8_t hash[SHA256_HASH_SIZE];
		attestation_evidence_t evidence;

		/* There is no evidence in tls_wrapper_nulltls */
		strncpy(evidence.type, "nulltls", sizeof(evidence.type));

		err = tls_wrapper_verify_certificate_extension(ctx, &evidence, hash,
							       SHA256_HASH_SIZE);
		if (err != TLS_WRAPPER_ERR_NONE) {
			ETLS_ERR("ERROR: failed to verify certificate extension\n");
			return err;
		}
	}
	return TLS_WRAPPER_ERR_NONE;
}
