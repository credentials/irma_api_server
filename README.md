# IRMA API server

This is a server that sits between IRMA tokens such as the [card emulator app](https://github.com/credentials/irma_android_cardemu) on the one hand, and service or identity providers on the other hand. It handles all IRMA-specific cryptographic details of issuing credentials and verifying disclosure proofs on behalf of the service or identity provider.

The API that this server offers is described [here](https://credentials.github.io/proposals/irma-without-apdus).

# Experimental

This project is very new and still in heavy development. It is _not_ yet suitable for deployment.

# Running the server

The gradle build file should take care the dependencies. To run the server in development mode simply call:

    gradle appRun

## Generating RSA keys

In the case of verification the server returns JSON web tokens signed using RSA, so you should generate an RSA public-private keypair before running the server. The private key of this pair must be put in `src/main/resources`. Using `openssl`, you can generate such a pair as follows.

```bash
cd src/main/resources

# Generate a private key in PEM format
openssl genrsa 2048 -out sk.pem
# Convert it to DER for Java
openssl pkcs8 -topk8 -inform PEM -outform DER -in sk.pem -out sk.der -nocrypt
# Calculate corresponding public key, saved in PEM format
openssl rsa -in sk.pem -pubout -outform PEM -out pk.pem
# Calculate corresponding public key, saved in DER format
openssl rsa -in sk.pem -pubout -outform DER -out pk.der
rm sk.pem
```

You can use the public key `pk.pem` or `pk.der` to check the validity of the JSON web tokens. (The `irma_verification_server` has no need of these two keys so they can safely be deleted from this directory - except when running the unit tests; then `pk.der` is needed to check the validity of the JSON web tokens.)

As to issuing, identity providers must send their requests to the server in the form of JSON web tokens. Thus the server needs to know the public keys of all authorized identity providers. These are also stored in `src/main/resources`; see the configuration file (and the section below) for details. Such keys kan be generated using `openssl` as above.

## Configuring the server
The server can be configured using a json file at `src/main/resources/config.json`. In the same directory a sample configuration file called `config.SAMPLE.json` is included, showing all options, their defaults, and what they mean.

## irma_configuration

Download or link the `irma_configuration` project to `src/main/resources/`.

See the credentials/irma_configuration project for the specifics. Remember that you can check out a different branch to get a different set of credentials and corresponding keys. In particular, the demo branch contains keys for all the issuers as well, thus making it very easy to test and develop applications.

# Testing

A test service provider and identity provider, written in node.js, is included; see `testsp.js` and `testip.js` respectively. Assuming you have node.js installed, you can run it by `js testsp.js url-to-server` (perhaps after running `npm install qrcode-terminal request jsonwebtoken fs`).

For more sophisticated examples, see [irma_js](https://github.com/credentials/irma_js).

# Testing with cURL

To make a GET request on a resource:

    curl -i -H "Accept: application/json" http://localhost:8080/irma_verification_server/api/hello/json

To make a POST request on a resource:

    curl -X POST -H "Content-Type: application/json" -d '{"a": 5.0,"b": -22.0}' http://localhost:8080/irma_verification_server_jersey/api/hello/json
