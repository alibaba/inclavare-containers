![inclavare-containers](docs/image/logo.png)

Inclavare Containers is an innovation of container runtime with the novel approach for launching protected containers in hardware-assisted Trusted Execution Environment (TEE) technology, aka Enclave, which can prevent the untrusted entity, such as Cloud Service Provider (CSP), from accessing the sensitive and confidential assets in use.

Inclavare Containers has the following salient features:

- Confidential computing oriented. Inclavare Containers provides a general design for the protection of tenant’s workload. 
  - Create the hardware-enforced isolation between tenant’s workload and privileged software controlled by CSP.
  - Remove CSP from the Trusted Computing Base (TCB) of tenant in untrusted cloud.
  - Construct the general attestation infrastructure to convince users to trust the workloads running inside TEE based on hardware assisted enclave technology.
- OCI-compliant. The component `rune` is [fully compliant](https://github.com/opencontainers/runtime-spec/blob/master/implementations.md#runtime-container) with OCI Runtime specification.
- Cloud platform agnostic. It can be deployed in any public cloud Kubernetes platform.

Please refer to [Terminology](docs/design/terminology.md) for more technical expressions used in Inclavare Containers.

# Audience

Inclavare Containers is helping to keep tenants' confidential data secure so they feel confident that their data is not being exposed to CSP or their own insiders, and they can easily move their trusted applications to the cloud.

# Architecture

Inclavare Containers follows the classic container runtime design. It takes the adaption to [containerd](https://github.com/containerd/containerd) as first class, and uses dedicated [shim-rune](https://github.com/alibaba/inclavare-containers/tree/master/shim) to interface with OCI Runtime [rune](https://github.com/alibaba/inclavare-containers/tree/master/rune). In the downstrem, [init-runelet](docs/design/terminology.md#init-runelet) employs a novel approach of launching [enclave runtime](docs/design/terminology.md#enclave-runtime) and trusted application in hardware-enforced enclave.

![architecture](docs/design/architecture.png)

The major components of Inclavare Containers are:

- rune  
  rune is a CLI tool for spawning and running enclaves in containers according to the OCI specification. rune is already written into [OCI Runtime implementation list](https://github.com/opencontainers/runtime-spec/blob/master/implementations.md#runtime-container).

- shim-rune  
  shim-rune resides in between containerd and `rune`, conducting enclave signing and management beyond the normal `shim` basis. In particular shim-rune and `rune` can compose a basic enclave containerization stack for confidential computing, providing low barrier to the use of confidential computing and the same experience as ordinary container. Please refer to [this doc](shim/README.md) for the details.

- enclave runtime  
  The backend of `rune` is a component called enclave runtime, which is responsible for loading and running trusted and protected applications inside enclaves. The interface between `rune` and enclave runtime is [Enclave Runtime PAL API](rune/libenclave/internal/runtime/pal/spec.md), which allows invoking enclave runtime through well-defined functions. The softwares for confidential computing may benefit from this interface to interact with cloud-native ecosystem.  
  
  One typical class of enclave runtime implementations is based on Library OSes. Currently, the recommended enclave runtime interacting with `rune` is [Occlum](https://github.com/occlum/occlum), a memory-safe, multi-process Library OS for Intel SGX.  
  
  In addition, you can write your own enclave runtime with any programming language and SDK (e.g, [Intel SGX SDK](https://github.com/intel/linux-sgx)) you prefer as long as it implements Enclave Runtime PAL API.

# Non-core components 

- sgx-tools  
  sgx-tools is a CLI tool, used to interact Intel SGX AESM service to retrieve various materials such as launch token, quoting enclave's target information, enclave quote and remote attestation report from IAS. Refer to [this tutorial](sgx-tools/README.md) for the details about its usage.

# Roadmap

Please refer to [Inclavare Containers Roadmap](ROADMAP.md) for the details. This document outlines the development roadmap for the Inclavare Containers project.

# Building

Please follow the command to build Inclavare Containers from the latested source code on your system. 

1. Download the latest source code of Inclavare Containers
```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
```

2. Prepare the tools required by Inclavare Containers
```shell
cd inclavare-containers

# install Go protobuf plugin for protobuf3
go get github.com/golang/protobuf/protoc-gen-go@v1.3.5
```

3. Build Inclavare Containers
```shell
# build rune, shim-rune and sgx-tools
make
```

# Installing

After build Inclavare Containers on your system, you can use the following command to install Inclavare Containers on your system.

```shell
sudo make install
```

`rune` will be installed to `/usr/local/sbin/rune` on your system. `shim-rune` will be installed to `/usr/local/bin/containerd-shim-rune-v2`. `sgx-tools` will be installed to `/usr/local/bin/sgx-tools`.

If you don't want to build and install Inclavare Containers from latest source code. We also provide RPM/DEB repository to help you install Inclavare Containers quickly. Please see the [steps about how to configure repository](https://github.com/alibaba/inclavare-containers/blob/master/docs/create_a_confidential_computing_kubernetes_cluster_with_inclavare_containers.md#1-add-inclavare-containers-repository) firstly. Then you can run the following command to install Inclavare Containers on your system.

- On CentOS 8.1

```shell
sudo yum install rune shim-rune sgx-tools
``` 

- On Ubuntu 18.04 server

```
sudo apt-get install rune shim-rune sgx-tools
```

# Integrating

Inclavare Containers can be integrated with dockerd and containerd.

## dockerd

Add the assocated configurations for `rune` in dockerd config file, e.g, `/etc/docker/daemon.json`, on your system.

```json
{
        "runtimes": {
                "rune": {
                        "path": "/usr/bin/rune",
                        "runtimeArgs": []
                }
        }
}
```

then restart dockerd on your system. If you install Inclavare Containers based on source code, please specify the path of rune as `/usr/local/sbin/rune` instead.

You can check whether `rune` is correctly enabled or not with:

```shell
docker info | grep rune
```

## containerd 

Add the assocated configurations for shim-rune in containerd config file, e.g, `/etc/containerd/config.toml`, on your system.

```toml
        [plugins.cri.containerd]
          ...
          [plugins.cri.containerd.runtimes.rune]
            runtime_type = "io.containerd.rune.v2"
```

then restart containerd on your system.

# Running

[The reference container images](https://hub.docker.com/u/inclavarecontainers) are available for the demonstration purpose to show how Inclavare Containers works. Currently, web application demos based on OpenJDK 11, [Dragonwell](http://dragonwell-jdk.io/), and Golang are provided.

# Tutorials

## Confidential Computing Kubernetes Cluster

Please refer to [this guide](docs/develop_and_deploy_hello_world_application_in_kubernetes_cluster.md) to deploy an enclave container in a Kubernetes cluster.

## Occlum LibOS

Please refer to [this guide](docs/Running_Occlum_with_Docker_and_OCI_Runtime_rune.md) to run [Occlum](https://github.com/occlum/occlum) with `rune`.
