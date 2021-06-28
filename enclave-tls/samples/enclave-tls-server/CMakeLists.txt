# Project name
project(enclave-tls-server)

if(NOT SGX)
    set(CMAKE_C_FLAGS "-fPIE ${CMAKE_C_FLAGS}")
endif()

if(BUILD_SAMPLES)
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/enclave-tls
                     ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}
                     ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/edl
                     ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/enclave-tls
                     )
    set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                     ${ENCLAVE_TLS_INSTALL_LIB_PATH}
                     )
    if(SGX)
        list(APPEND LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src/sgx/untrust
                                 ${CMAKE_BINARY_DIR}/samples/sgx-stub-enclave
                                 )

        set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave
                             ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                             )

        set(DEPEND_TRUSTED_LIBS ${CMAKE_BINARY_DIR}/src/sgx/untrust/libenclave_tls_u.a)
    endif()
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

    set(INCLUDE_DIRS ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH})
    set(LIBRARY_DIRS ${ENCLAVE_TLS_INSTALL_LIB_PATH})

    if(SGX)
        set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave
                             ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
			     )
    endif()
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES server.c)

# Generate bin file
if(SGX)
    set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave/sgx_stub.edl)
    add_untrusted_executable(${PROJECT_NAME}
                             SRCS ${SOURCES}
                             UNTRUSTED_LIBS ${DEPEND_TRUSTED_LIBS}
                             EDL ${EDLS}
                             EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                             )
    add_dependencies(${PROJECT_NAME} sgx_stub_enclave-sign)
else()
    add_executable(${PROJECT_NAME} ${SOURCES})
    target_link_libraries(${PROJECT_NAME} enclave_tls)
endif()

install(TARGETS ${PROJECT_NAME}
	DESTINATION /usr/share/enclave-tls/samples)
