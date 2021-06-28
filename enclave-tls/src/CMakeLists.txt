# Add third party and instance directory
add_subdirectory(external)
add_subdirectory(crypto_wrappers)
add_subdirectory(attesters)
add_subdirectory(verifiers)
add_subdirectory(tls_wrappers)
if(SGX)
    add_subdirectory(sgx)
endif()

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/internal
                 )
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust)
endif()
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/etls_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/etls_core_generate_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_cleanup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_negotiate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_receive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_transmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/api/crypto_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/etls_crypto_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/etls_crypto_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/etls_crypto_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/etls_tls_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/etls_tls_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/etls_tls_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/tls_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/api/enclave_attester_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/enclave_attester.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/etls_enclave_attester_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/etls_enclave_attester_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/etls_enclave_attester_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/api/enclave_verifier_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/enclave_verifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/etls_enclave_verifier_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/etls_enclave_verifier_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/etls_enclave_verifier_select.c
    )
if(SGX)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/etls_syscalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/sgx_ecdsa_ecalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/sgx_dummy.c
                        )
endif()
if(NOT SGX)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/util/sgxutils.c)
endif()

# Static library dependencies
if(SGX)
    set(DEPEND_TRUSTED_LIBS etls_edl_t
                            wolfssl_sgx
                            crypto_wrapper_nullcrypto
                            crypto_wrapper_wolfcrypt
                            tls_wrapper_nulltls
                            tls_wrapper_wolfssl
                            attester_nullattester
                            attester_sgx_ecdsa
                            attester_sgx_la
                            verifier_nullverifier
                            verifier_sgx_ecdsa
                            verifier_sgx_ecdsa_qve
                            verifier_sgx_la
                            )
endif()

# Generate library
if(SGX)
    add_trusted_library(${ETLS_LIB} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
    add_dependencies(${ETLS_LIB} ${DEPEND_TRUSTED_LIBS})
else()
    add_library(${ETLS_LIB} SHARED ${SOURCES})
    target_link_libraries(${ETLS_LIB} ${ENCLAVE_TLS_LDFLAGS})
    set_target_properties(${ETLS_LIB} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install lib
install(TARGETS ${ETLS_LIB}
        DESTINATION ${ENCLAVE_TLS_INSTALL_LIB_PATH})

# Install header
set(ETLS_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/api.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/cert.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/crypto_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/attester.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/verifier.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/err.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/log.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/sgx.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls/tls_wrapper.h
                       )
install(DIRECTORY DESTINATION ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/enclave-tls)
install(FILES ${ETLS_INCLUDE_FILES}
	DESTINATION ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/enclave-tls)

# Install edl
if(SGX)
    set(ETLS_EDL_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/etls.edl
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/etls_syscalls.edl
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_dummy.edl
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_ecdsa.edl
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_la.edl
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/etls_syscalls.h
                       )
    install(DIRECTORY DESTINATION ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/edl)
    install(FILES ${ETLS_EDL_FILES}
    	    DESTINATION ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/edl)
endif()
