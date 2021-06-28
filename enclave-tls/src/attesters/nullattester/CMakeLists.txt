# Project name
project(attester_nullattester)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 )
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
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            collect_evidence.c
            init.c
            main.c
            pre_init.c
            )

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${ENCLAVE_TLS_LDFLAGS} ${ETLS_LIB})
endif()

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${ENCLAVE_TLS_INSTALL_LIBEQ_PATH})
