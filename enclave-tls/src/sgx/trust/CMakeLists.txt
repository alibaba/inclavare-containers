# Project name
project(etls_edl_t)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                 ${CMAKE_BINARY_DIR}/src/sgx/trust
                 )
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES sgx_dummy.c
            etls_syscalls.c
            sgx_ecdsa_ecalls.c
            )

# Generate library
set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl)
set(ETLS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl/etls.edl)
add_trusted_library(${PROJECT_NAME}
                    SRCS ${SOURCES}
                    EDL ${ETLS_EDL}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
		    )
