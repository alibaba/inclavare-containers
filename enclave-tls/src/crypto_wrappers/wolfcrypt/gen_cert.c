#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/cert.h>
#include "wolfcrypt.h"

/* *INDENT-OFF* */
crypto_wrapper_err_t __secured
wolfcrypt_gen_cert(crypto_wrapper_ctx_t *ctx,
		   enclave_tls_cert_info_t *cert_info)
{
	ETLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	Cert crt;
	wc_InitCert(&crt);

	cert_subject_t *subject = &cert_info->subject;
	strncpy(crt.subject.org, subject->organization,
		sizeof(crt.subject.org) - 1);
	crt.subject.org[sizeof(crt.subject.org) - 1] = '\0';
	strncpy(crt.subject.unit, subject->organization_unit,
		sizeof(crt.subject.unit) - 1);
	crt.subject.unit[sizeof(crt.subject.unit) - 1] = '\0';
	strncpy(crt.subject.commonName, subject->common_name,
		sizeof(crt.subject.commonName) - 1);
	crt.subject.commonName[sizeof(crt.subject.commonName) - 1] = '\0';

	ETLS_DEBUG("evidence type %s\n", cert_info->evidence.type);

	/* FIXME: add the handle of different quote types */
	if (!strcmp(cert_info->evidence.type, "sgx-epid")) {
		attestation_verification_report_t *epid = &cert_info->evidence.epid;

		assert(sizeof(crt.iasAttestationReport) >= epid->ias_report_len);
		memcpy(crt.iasAttestationReport, epid->ias_report, epid->ias_report_len);
		crt.iasAttestationReportSz = epid->ias_report_len;

		assert(sizeof(crt.iasSigCACert) >= epid->ias_sign_ca_cert_len);
		memcpy(crt.iasSigCACert, epid->ias_sign_ca_cert, epid->ias_sign_ca_cert_len);
		crt.iasSigCACertSz = epid->ias_sign_ca_cert_len;

		assert(sizeof(crt.iasSigCert) >= epid->ias_sign_cert_len);
		memcpy(crt.iasSigCert, epid->ias_sign_cert, epid->ias_sign_cert_len);
		crt.iasSigCertSz = epid->ias_sign_cert_len;

		assert(sizeof(crt.iasSig) >= epid->ias_report_signature_len);
		memcpy(crt.iasSig, epid->ias_report_signature, epid->ias_report_signature_len);
		crt.iasSigSz = epid->ias_report_signature_len;
	} else if (!strcmp(cert_info->evidence.type, "sgx_ecdsa")) {
		ecdsa_attestation_evidence_t *ecdsa = &cert_info->evidence.ecdsa;

		memcpy(crt.quote, ecdsa->quote, ecdsa->quote_len);
		crt.quoteSz = ecdsa->quote_len;
	} else if (!strcmp(cert_info->evidence.type, "sgx-la")) {
		/* TODO */
	}

	RNG rng;
	wc_InitRng(&rng);
	wolfcrypt_ctx_t *wc_ctx = (wolfcrypt_ctx_t *)ctx->crypto_private;
	cert_info->cert_len = wc_MakeSelfCert(&crt, cert_info->cert_buf,
					      sizeof(cert_info->cert_buf),
					      &wc_ctx->secured->key, &rng);
	if (cert_info->cert_len <= 0) {
		ETLS_DEBUG("failed to create self-signing certificate %d\n", cert_info->cert_len);
		return WOLFCRYPT_ERR_CODE(cert_info->cert_len);
	}

	ETLS_DEBUG("self-signing certificate generated\n");

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */