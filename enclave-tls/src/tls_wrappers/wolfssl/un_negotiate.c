/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

/* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */
static const int rsa_pub_3072_raw_der_len = 398;

#ifdef WOLFSSL_SGX_WRAPPER
void *memmem(void *start, unsigned int s_len, void *find, unsigned int f_len)
{
	char *p, *q;
	unsigned int len;
	p = start, q = find;
	len = 0;
	while ((p - (char *)start + f_len) <= s_len) {
		while (*p++ == *q++) {
			len++;
			if (len == f_len)
				return (p - f_len);
		};
		q = find;
		len = 0;
	};
	return (NULL);
}
#endif

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
int find_oid(const unsigned char *ext, size_t ext_len, const unsigned char *oid, size_t oid_len,
	     unsigned char **val, size_t *len)
{
	uint8_t *p = memmem((void *)ext, ext_len, (void *)oid, oid_len);

	if (!p)
		return -1;

	p += oid_len;

	int i = 0;

	// Some TLS libraries generate a BOOLEAN for the criticality of the extension.
	if (p[i] == 0x01) {
		assert(p[i++] == 0x01); // tag, 0x01 is ASN1 Boolean
		assert(p[i++] == 0x01); // length
		assert(p[i++] == 0x00); // value (0 is non-critical, non-zero is critical)
	}

	// Now comes the octet string
	assert(p[i++] == 0x04); // tag for octet string
	assert(p[i++] == 0x82); // length encoded in two bytes
	*len = p[i++] << 8;
	*len += p[i++];
	*val = &p[i++];

	return 1;
}

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
int extract_x509_extension(const uint8_t *ext, int ext_len, const uint8_t *oid, size_t oid_len,
			   uint8_t *data, uint32_t *data_len, uint32_t data_max_len)
{
	uint8_t *ext_data;
	size_t ext_data_len;

	int rc = find_oid(ext, ext_len, oid, oid_len, &ext_data, &ext_data_len);
	if (rc == -1 || ext_data == NULL || ext_data_len > data_max_len)
		return -1;

	memcpy(data, ext_data, (uint32_t)ext_data_len);
	*data_len = (uint32_t)ext_data_len;

	return 1;
}

/**
 * Extract all extensions.
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
static int extract_cert_extensions(const uint8_t *ext, int ext_len,
				   attestation_evidence_t *evidence)
{
	if (!strcmp(evidence->type, "sgx_epid")) {
		int rc = extract_x509_extension(ext, ext_len, ias_response_body_oid, ias_oid_len,
						evidence->epid.ias_report,
						&evidence->epid.ias_report_len,
						sizeof(evidence->epid.ias_report));
		if (rc != 1)
			return rc;

		rc = extract_x509_extension(ext, ext_len, ias_root_cert_oid, ias_oid_len,
					    evidence->epid.ias_sign_ca_cert,
					    &evidence->epid.ias_sign_ca_cert_len,
					    sizeof(evidence->epid.ias_sign_ca_cert));
		if (rc != 1)
			return rc;

		rc = extract_x509_extension(ext, ext_len, ias_leaf_cert_oid, ias_oid_len,
					    evidence->epid.ias_sign_cert,
					    &evidence->epid.ias_sign_cert_len,
					    sizeof(evidence->epid.ias_sign_cert));
		if (rc != 1)
			return rc;

		rc = extract_x509_extension(ext, ext_len, ias_report_signature_oid, ias_oid_len,
					    evidence->epid.ias_report_signature,
					    &evidence->epid.ias_report_signature_len,
					    sizeof(evidence->epid.ias_report_signature));
		return rc;
	} else if (!strcmp(evidence->type, "sgx_ecdsa")) {
		return extract_x509_extension(ext, ext_len, ecdsa_quote_oid, ias_oid_len,
					      evidence->ecdsa.quote, &evidence->ecdsa.quote_len,
					      sizeof(evidence->ecdsa.quote));
	} else if (!strcmp(evidence->type, "sgx_la")) {
		return extract_x509_extension(ext, ext_len, la_report_oid, ias_oid_len,
					      evidence->la.report, &evidence->la.report_len,
					      sizeof(evidence->la.report));
	}

	return 1;
}

crypto_wrapper_err_t sha256_rsa_pubkey(unsigned char hash[SHA256_DIGEST_SIZE], RsaKey *key)
{
	uint8_t buf[1024];

	/* SetRsaPublicKey() only exports n and e without wrapping them in
	   additional ASN.1 (PKCS#1). */
	int pub_rsa_key_der_len = SetRsaPublicKey(buf, key, sizeof(buf), 0);
	if (pub_rsa_key_der_len != rsa_pub_3072_raw_der_len)
		return -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;

	Sha256 sha;
	wc_InitSha256(&sha);
	wc_Sha256Update(&sha, buf, pub_rsa_key_der_len);
	wc_Sha256Final(&sha, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}

static crypto_wrapper_err_t calc_pubkey_hash(DecodedCert *crt, enclave_tls_cert_algo_t algo,
					     uint8_t *hash)
{
	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;

	RsaKey rsaKey;
	wc_InitRsaKey(&rsaKey, NULL);

	unsigned int idx = 0;
	int ret = wc_RsaPublicKeyDecode(crt->publicKey, &idx, &rsaKey, crt->pubKeySize);
	if (ret)
		return WOLFCRYPT_ERR_CODE(ret);

	crypto_wrapper_err_t err = sha256_rsa_pubkey(hash, &rsaKey);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	wc_FreeRsaKey(&rsaKey);

	return CRYPTO_WRAPPER_ERR_NONE;
}

#ifdef WOLFSSL_SGX_WRAPPER
int verify_certificate(void *ctx, uint8_t *der_cert, uint32_t der_cert_len)
{
	tls_wrapper_ctx_t *tls_ctx = ctx;
#else
int verify_certificate(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
	(void)preverify;

	const uint8_t *der_cert = store->certs->buffer;
	uint32_t der_cert_len = store->certs->length;
	tls_wrapper_ctx_t *tls_ctx = (tls_wrapper_ctx_t *)store->userCtx;
#endif

	DecodedCert crt;
	InitDecodedCert(&crt, (byte *)der_cert, der_cert_len, NULL);

	int ret = ParseCert(&crt, CERT_TYPE, NO_VERIFY, 0);
	if (ret) {
		ETLS_DEBUG("ParseCertRelative error with code %d\n", ret);
		return 0;
	}

	/* FIXME: add the ability to define different hash_size acording to cert_algo */
	enclave_tls_cert_algo_t cert_algo = ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256;
	unsigned int hash_size;
	if (cert_algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		hash_size = SHA256_HASH_SIZE;
	else
		return 0;

	uint8_t hash[hash_size];
	calc_pubkey_hash(&crt, cert_algo, hash);

	/* Extract the Enclave TLS certificate extension from the TLS certificate
	 * extension and parse it into evidence
	 */
	attestation_evidence_t evidence;
	uint8_t *ext_data;
	size_t ext_data_len;

	if (find_oid(der_cert, der_cert_len, ecdsa_quote_oid, ias_oid_len, &ext_data,
		     &ext_data_len) == 1)
		strncpy(evidence.type, "sgx_ecdsa", sizeof(evidence.type));
	else if (find_oid(der_cert, der_cert_len, la_report_oid, ias_oid_len, &ext_data,
			  &ext_data_len) == 1)
		strncpy(evidence.type, "sgx_la", sizeof(evidence.type));
	else
		strncpy(evidence.type, "nullverifier", sizeof(evidence.type));

	int rc = extract_cert_extensions(crt.extensions, crt.extensionsSz, &evidence);
	if (rc != 1) {
		ETLS_ERR("ERROR: extract_cert_extensions %d\n", rc);
		return 0;
	}

	tls_wrapper_err_t err =
		tls_wrapper_verify_certificate_extension(tls_ctx, &evidence, hash, hash_size);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("failed to verify certificate extension %#x\n", err);
		return 0;
	}

	FreeDecodedCert(&crt);

	return 1;
}
