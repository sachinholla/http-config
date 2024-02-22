#!/usr/bin/env bash

set -e

GROUP_NAMES=( X Y )
PER_GROUP=2

if [[ ${PWD} != */testdata ]]; then
    mkdir -p testdata
    cd testdata
fi

for G in ${GROUP_NAMES[@]}; do
    g=${G,,}
    SERIAL_PFX=${RANDOM}
    CA_KEY=ca${G}_key.pem
    CA_CRT=ca${G}_crt.pem

    # Generate the root CA certificate
    openssl req -x509 -new -newkey rsa:2048 -nodes -sha256 -days 9999 \
        -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=sachinholla/CN=ca.example.com" \
        -out ${CA_CRT} -keyout ${CA_KEY} \
        -addext "keyUsage = digitalSignature, keyEncipherment, keyCertSign" \
        -addext "extendedKeyUsage = serverAuth, clientAuth"

    for C in $(seq 1 ${PER_GROUP}); do
        CSR_NAME=${g}${C}.csr
        CRT_NAME=${g}${C}_crt.pem
        KEY_NAME=${g}${C}_key.pem

        # Create CSR for server & client certs
        openssl req -new -newkey rsa:2048 -nodes -sha256 \
            -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=sachinholla/CN=example.com" \
            -out ${CSR_NAME} -keyout ${KEY_NAME}

        # Sign CSR using the above root CA
        openssl x509 -req -days 9999 -sha256 \
            -CA ${CA_CRT} -CAkey ${CA_KEY} \
            -in ${CSR_NAME} -out ${CRT_NAME} \
            -set_serial ${SERIAL_PFX}00000$C
    done
done
