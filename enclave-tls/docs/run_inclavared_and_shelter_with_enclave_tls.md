This guide shows you how to run [inclavared](https://github.com/alibaba/inclavare-containers/tree/master/inclavared) and [shelter](https://github.com/alibaba/inclavare-containers/tree/master/shelter) with `Enclave-TLS`.

# Before you start

- Occlum-attestation-agent  
  Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/enclave-tls/docs/run_enclave_tls_with_occlum.md#building-occlum-container-image) to build occlum-attestation-agent image.

- Inclavared  
  Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/inclavared/README.md#build) to build and install `inclavared`.

- Shelter  
  Please refer to [this guild](https://github.com/alibaba/inclavare-containers/blob/master/shelter/README.md) to build and install `shelter`.

# Run

## Run occlum-attestation-agent

```shell
docker run -it --rm --runtime=rune --net host \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/opt/occlum/build/lib/libocclum-pal.so.0.21.0 \
  -e ENCLAVE_RUNTIME_ARGS=occlum_workspace_server \
  occlum-app --mutual
```

The default enclave mode is `debug`. Please specify `-e OCCLUM_RELEASE_ENCLAVE=1` if using a product enclave.

`occlum-attestation-agent` responds to the request from `inclavared`, then sends the attestation evidence (mrenclave and mrsigner value) of confidential container to `inclavared`.

## Run inclavared

Inclavared is responsible for forwarding the traffic between the downstream confidential container `occlum-attestation-agent` and the upstream verifier `shelter`. The communication process is protected by the attested `Enclave-TLS` channel.

```shell
inclavared --listen 127.0.0.1:1236 --xfer 127.0.0.1:1234 --attester sgx_ecdsa_qve --verifier sgx_ecdsa_qve --mutual
```

Inclavared will listen the request from the remote attestation client `shelter` at `127.0.0.1:1236`. After receiving the request, inclavared will request the `occlum-attestation-agent` which is listening on `127.0.0.1:1234`.

## Run shelter

```shell
shelter remoteattestation --addr=tcp://127.0.0.1:1236 --verifier sgx_ecdsa --tls wolfssl  --crypto wolfcrypt
```

Shelter, as the attestation verifier on the off-cloud side, records the launch measurements of enclave runtime, and afterward establishes `Enclave-TLS` trusted channel to communicate with inclavared. Eventually, it retrieves the evidence about enclave runtimes for verification.

The expected output message `Remote attestation is successful` means the verification is successful and the confidential container is running inside a trusted HW-TEE.
