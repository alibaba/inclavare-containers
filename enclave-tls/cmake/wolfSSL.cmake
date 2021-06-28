# Project name
if(SGX)
    project(wolfssl_sgx)
else()
    project(wolfssl-v4.6.0)
endif()
#project(wolfssl-v4.6.0-stable)

include(ExternalProject)

set(WOLFSSL_VERSION "24.3.0")
set(WOLFSSL_VERSION_MAJOR 24)
set(WOLFSSL_VERSION_MINOR 3)
set(WOLFSSL_VERSION_PATCH 0)

set(WOLFSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# Set wolfssl configure flags
set(WOLFSSL_CONFIGURE_FLAGS "--prefix=${WOLFSSL_ROOT} \
--enable-writedup --enable-shared --enable-static \
--enable-keygen --enable-certgen --enable-certext \
--with-pic --disable-examples --disable-crypttests \
--enable-aesni --enable-tlsv10"
)
#if(DEBUG)
    set(WOLFSSL_CONFIGURE_FLAGS "${WOLFSSL_CONFIGURE_FLAGS} --enable-debug")
#endif()

# Configure
set(_configure_script "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl_configure.sh")
file(WRITE "${_configure_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME}
patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patch/wolfssl.patch
./autogen.sh
CFLAGS=\"${WOLFSSL_CFLAGS}\" ./configure ${WOLFSSL_CONFIGURE_FLAGS}
cd -
")

set(_configure_cmake "${CMAKE_CURRENT_SOURCE_DIR}/configure.cmake")
file(WRITE "${_configure_cmake}"
"execute_process(COMMAND sh ${_configure_script} WORKING_DIRECTORY ${WOLFSSL_ROOT}/src/${PROJECT_NAME})"
)

# Make
set(_make_script "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl_make.sh")
if(SGX)
    file(WRITE "${_make_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME}
make
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME}/IDE/LINUX-SGX
make -f sgx_t_static.mk CFLAGS=\"${WOLFSSL_SGX_CFLAGS}\"
")
else()
    file(WRITE "${_make_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME} && make
")
endif()

set(_make_cmake "${CMAKE_CURRENT_SOURCE_DIR}/make.cmake")
file(WRITE "${_make_cmake}"
"execute_process(COMMAND sh ${_make_script} WORKING_DIRECTORY ${WOLFSSL_ROOT}/src/${PROJECT_NAME})"
)

# Install
set(_install_script "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl_install.sh")
if(SGX)
    file(WRITE "${_install_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME} && make install
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/include
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl
install -m 0755 ${WOLFSSL_ROOT}/include/wolfssl/*.h ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl/
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl/wolfcrypt
install -m 0755 ${WOLFSSL_ROOT}/include/wolfssl/wolfcrypt/*.h ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl/wolfcrypt/
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib
install -m 0755 ${WOLFSSL_ROOT}/src/${PROJECT_NAME}/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib/libwolfssl_sgx.a
cd -
")
else()
    file(WRITE "${_install_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME} && make install
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/include
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl
install -m 0755 ${WOLFSSL_ROOT}/include/wolfssl/*.h ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl/
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl/wolfcrypt
install -m 0755 ${WOLFSSL_ROOT}/include/wolfssl/wolfcrypt/*.h ${CMAKE_BINARY_DIR}/src/external/wolfssl/include/wolfssl/wolfcrypt/
install -d -m 0755 ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib
install -m 0755 ${WOLFSSL_ROOT}/lib/libwolfssl*.a* ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib/
install -m 0755 ${WOLFSSL_ROOT}/lib/libwolfssl*.so* ${CMAKE_BINARY_DIR}/src/external/wolfssl/lib/
cd -
")
endif()

set(_install_cmake "${CMAKE_CURRENT_SOURCE_DIR}/install.cmake")
file(WRITE "${_install_cmake}"
"execute_process(COMMAND sh ${_install_script} WORKING_DIRECTORY ${WOLFSSL_ROOT}/src/${PROJECT_NAME})"
)

# Set wolfssl git and comiple parameters
set(WOLFSSL_URL           https://github.com/wolfSSL/wolfssl/archive/refs/tags/v4.6.0-stable.zip)
set(WOLFSSL_DOWNLOAD_NAME wolfssl-v4.6.0-stable.zip)
set(WOLFSSL_MAKE          cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME} && make)

ExternalProject_Add(${PROJECT_NAME}
    PREFIX            ${WOLFSSL_ROOT}
    URL               ${WOLFSSL_URL}
    URL_HASH          SHA256=c3f65b0e610ce3e1c02646724189fab23c6d5e73c019de52f42dc32a116def52
    DOWNLOAD_NAME     ${WOLFSSL_DOWNLOAD_NAME}
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -P ${_configure_cmake}
    BUILD_COMMAND     ${CMAKE_COMMAND} -P ${_make_cmake}
    INSTALL_COMMAND   ${CMAKE_COMMAND} -P ${_install_cmake}
    )
