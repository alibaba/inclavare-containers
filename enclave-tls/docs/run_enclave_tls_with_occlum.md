This guide will show you how to run the **ecdsa baesd remote attestation** server on Occlum Libos and `rune`.

# Before you start

1. It is recommended to develop in the Occlum image.

```shell
docker run -it --privileged --network host \
  -v /dev/sgx_enclave:/dev/sgx/enclave \
  -v /dev/sgx_provision:/dev/sgx/provision \
  -v /var/run/aesmd:/var/run/aesmd \
  occlum/occlum:0.21.0-ubuntu18.04
```

2. Please refer to [this guide](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md) to install DCAP. Note: If your platform is pre-product SGX platform (SBX), please follow [this guide](https://github.com/alibaba/inclavare-containers/blob/master/hack/use-sbx-platform/README.md) to resolve the quote verification problem on SBX platforms. 

3. After you resolve the quote verification problem on SBX platforms, please to recompile Occlum using the following command:

```shell
cd occlum
make submodule && OCCLUM_RELEASE_BUILD=1 make install
```


# Quick start

1. Download the latest source code of Enclave TLS

```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
```

2. Build and install Enclave TLS

```shell
cd inclavare-containers/enclave-tls
make OCCLUM=1
make install
```

Note that the implementation of the Unix socket in Occlum is NOT complete yet. Occlum only supports the connection between the internal Unix sockets of Occlum.

In addition, Occlum only provides `occlum-go` to compile go program. While the enclave-tls is compiled based on `gcc`. In practice, using `occlum-go` to compile the `enclave-tls-server` program linked with enclave-tls will generate undefined symbol errors. Therefore we provide the server and client programs in C language for functional elaboration. With the continuous development of occlum functions, this will no longer be a problem.

# RUN Enclave Tls with Occlum and Rune

Right now, Enclave TLS running on Occlum Libos supports the following instance types:

| Priority | Tls Wrapper instances |     Attester instances    |     Verifier instances    | Crypto Wrapper Instance |
| -------- | --------------------- | ------------------------- | ------------------------- | ----------------------- |
| low      | nulltls               | nullattester              | nullverifier              | nullcrypto              |
| Medium   | wolfssl               | sgx\_ecdsa                | sgx\_ecdsa\_qve           | wolfcrypt               |


## Building Occlum container image

```shell
cd /usr/share/enclave-tls/samples

# 1. Init Occlum server Workspace
rm -rf occlum_workspace_server
mkdir occlum_workspace_server
cd occlum_workspace_server
occlum init

# 2. Copy files into Occlum Workspace and Build
cp ../enclave-tls-server image/bin
cp /lib/x86_64-linux-gnu/libdl.so.2 image/opt/occlum/glibc/lib
mkdir -p image/opt/enclave-tls
cp -rf /opt/enclave-tls/lib image/opt/enclave-tls

occlum build
occlum run /bin/enclave-tls-server -m -l debug
```

Type the following commands to generate a minimal, self-contained package (.tar.gz) for the Occlum instance.

```shell
cd occlum_workspace_server
occlum package occlum_instance.tar.gz
```

## Create Occlum container image

Now you can build your occlum container image in occlum\_workspace directory on your host system.

Type the following commands to create a `Dockerfile`:

```shell
cp /usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so ./
cp /usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so ./
cp /usr/lib/x86_64-linux-gnu/libsgx_qve.signed.so ./

cat >Dockerfile <<EOF
FROM ubuntu:18.04

RUN mkdir -p /run/rune
WORKDIR /run/rune

ADD occlum_instance.tar.gz /run/rune

COPY libsgx_pce.signed.so /usr/lib/x86_64-linux-gnu
COPY libsgx_qe3.signed.so /usr/lib/x86_64-linux-gnu
COPY libsgx_qve.signed.so /usr/lib/x86_64-linux-gnu/

ENTRYPOINT ["/bin/enclave-tls-server"]
EOF
```

then build the Occlum container image with the command:

```shell
docker build . -t occlum-app
```

## Integrate OCI Runtime rune with Docker

Please refer to [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton#integrate-oci-runtime-rune-with-docker) to integrate OCI runtime rune with docker.

## Running Occlum container image

```shell
docker run -it --rm --runtime=rune --net host \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/opt/occlum/build/lib/libocclum-pal.so \
  -e ENCLAVE_RUNTIME_ARGS=occlum_workspace_server \
  occlum-app -m
```

Note that `-m` option means build mutual remote attestation with client. You can remove `-m` to build one-way attestation.

## Run client

There are two way to run client.

### Run client based on Occlum

```shell
cd /usr/share/enclave-tls/samples

# 1. Init Occlum client Workspace
rm -rf occlum_workspace_client
mkdir occlum_workspace_client
cd occlum_workspace_client
occlum init

# 2. Copy files into Occlum Workspace and Build
cp ../enclave-tls-client image/bin
cp /lib/x86_64-linux-gnu/libdl.so.2 image/opt/occlum/glibc/lib
mkdir -p image/opt/enclave-tls
cp -rf /opt/enclave-tls/lib image/opt/enclave-tls

occlum build
occlum run /bin/enclave-tls-client -l debug -m
```

## Run client based on sgxsdk

```shell
cd "$WORKSPACE"/inclavare-containers/enclave-tls
make clean && make uninstall && make SGX=1 && make install
cd /usr/share/enclave-tls/samples
./enclave-tls-client -a sgx_ecdsa -m -l debug
```
