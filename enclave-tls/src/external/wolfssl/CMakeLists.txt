include(wolfSSL)

set(WOLFSSL_LIB_NAME wolfssl)
set(WOLFSSL_LIB_PATH ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib)
if(SGX)
    set(WOLFSSL_LIB_FILES ${WOLFSSL_LIB_PATH}/lib${WOLFSSL_LIB_NAME}_sgx.a)
else()
    set(WOLFSSL_LIB_FILES ${WOLFSSL_LIB_PATH}/lib${WOLFSSL_LIB_NAME}.a
                          ${WOLFSSL_LIB_PATH}/lib${WOLFSSL_LIB_NAME}.so
                          ${WOLFSSL_LIB_PATH}/lib${WOLFSSL_LIB_NAME}.so.${WOLFSSL_VERSION_MAJOR}
                          ${WOLFSSL_LIB_PATH}/lib${WOLFSSL_LIB_NAME}.so.${WOLFSSL_VERSION_MAJOR}.${WOLFSSL_VERSION_MINOR}.${WOLFSSL_VERSION_PATCH}
                          )
endif()

install(FILES ${WOLFSSL_LIB_FILES}
        DESTINATION ${ENCLAVE_TLS_INSTALL_LIB_PATH})
