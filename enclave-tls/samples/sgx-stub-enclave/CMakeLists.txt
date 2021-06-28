# Project name
project(sgx-stub-enclave)

if(BUILD_SAMPLES)
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/enclave-tls
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl)

    set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                     ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib
                     ${CMAKE_BINARY_DIR}/src/crypto_wrappers/nullcrypto
                     ${CMAKE_BINARY_DIR}/src/crypto_wrappers/wolfcrypt
                     ${CMAKE_BINARY_DIR}/src/tls_wrappers/nulltls
                     ${CMAKE_BINARY_DIR}/src/tls_wrappers/wolfssl
                     ${CMAKE_BINARY_DIR}/src/verifiers/nullverifier
                     ${CMAKE_BINARY_DIR}/src/verifiers/sgx-ecdsa
                     ${CMAKE_BINARY_DIR}/src/verifiers/sgx-ecdsa-qve
                     ${CMAKE_BINARY_DIR}/src/verifiers/sgx-la
                     ${CMAKE_BINARY_DIR}/src/attesters/nullattester
                     ${CMAKE_BINARY_DIR}/src/attesters/sgx-ecdsa
                     ${CMAKE_BINARY_DIR}/src/attesters/sgx-la

                     )

    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}
                         ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                         )
else()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    include(CustomInstallDirs)
    include(FindEnclaveTls)
    if(NOT ENCLAVE_TLS_FOUND)
        message(FATAL_ERROR "Failed to find enclave_tls!")
    endif()
    include(FindSGX)
    if(NOT SGX_FOUND)
        message(FATAL_ERROR "Failed to find sgx!")
    endif()
    include(CompilerOptions)
    include(SGXCommon)

    set(INCLUDE_DIRS ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/include
                     ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/include/enclave-tls
                     ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/include/edl
                     )

    set(LIBRARY_DIRS ${ENCLAVE_TLS_INSTALL_LIB_PATH})

    set(EDL_SEARCH_PATHS ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/edl)
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

set(E_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub_ecall.c)
set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub.edl)
set(LDS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub_enclave.lds)
set(DEPEND_TRUSTED_LIBS wolfssl_sgx
                        crypto_wrapper_nullcrypto
                        crypto_wrapper_wolfcrypt
                        tls_wrapper_nulltls
                        tls_wrapper_wolfssl
                        attester_nullattester
                        attester_sgx_ecdsa
                        attester_sgx_la
                        verifier_nullverifier
                        verifier_sgx_ecdsa
                        verifier_sgx_la
                        verifier_sgx_ecdsa_qve
                        enclave_tls
                        )

add_enclave_library(sgx_stub_enclave SRCS ${E_SRCS} EDL ${EDLS} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS} EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(sgx_stub_enclave KEY sgx_stub_enclave.pem CONFIG sgx_stub_enclave.xml)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sgx_stub_enclave.signed.so
        DESTINATION /usr/share/enclave-tls/samples)
