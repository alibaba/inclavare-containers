# Project name
project(verifier_sgx_ecdsa)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 ${CMAKE_CURRENT_SOURCE_DIR}
                 /usr/include
                 )
if(OCCLUM)
    list(APPEND INCLUDE_DIRS ${SGXSDK_INSTALL_INCLUDE_PATH})
endif()
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust
                             )
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${ENCLAVE_TLS_INSTALL_LIB_PATH}
                 )

if(OCCLUM)
    list(APPEND LIBRARY_DIRS ${SGXSDK_INSTALL_LIB_PATH})
endif()
link_directories(${LIBRARY_DIRS})

# Set extra link library
if(OCCLUM)
    set(EXTRA_LINK_LIBRARY sgx_dcap_quoteverify)
endif()

# Set source file
set(SOURCES cleanup.c
            init.c
            main.c
            pre_init.c
            verify_evidence.c
            )

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${ENCLAVE_TLS_LDFLAGS} ${ETLS_LIB})
endif()

# Install library
install(TARGETS ${PROJECT_NAME}
        DESTINATION ${ENCLAVE_TLS_INSTALL_LIBV_PATH})
