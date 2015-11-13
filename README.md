# Running the server

The gradle build file should take care of most of the dependencies. However, `irma_verification_common` is not yet available in the central IRMA repository, so you'll have to manually download and install it. To run the server in development mode simply call:

    gradle jettyRun

it is set up in such a way that it will automatically reload recompile class files. If your IDE already uses gradle to compile them this should work out of the box. Otherwise, simply call

    gradle javaCompile

and your app will be reloaded. Note that this is a lot faster than simply restarting the Jetty container.

# Generating RSA keys

The server returns JSON web tokens signed using RSA, so you should generate an RSA public-private keypair before running the server. The private key of this pair must be put in `src/main/resources`. Using `openssl`, you can generate such a pair as follows.

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

You can use the public key `pk.pem` or `pk.der` to check the validity of the JSON web tokens. (The `irma_verification_server` has no need of these two keys so they can safely be deleted from this directory.)

# Testing

A test service provider, written in node.js, is included; see `testsp.js`. Assuming you have node.js installed, you can run it by `js testsp.js url-to-server` (perhaps after running `npm install qrcode-terminal request jsonwebtoken fs`).

# Testing with cURL

To make a GET request on a resource:

    curl -i -H "Accept: application/json" http://localhost:8080/irma_verification_server/api/hello/json

To make a POST request on a resource:

    curl -X POST -H "Content-Type: application/json" -d '{"a": 5.0,"b": -22.0}' http://localhost:8080/irma_verification_server_jersey/api/hello/json

