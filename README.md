**Note: This project is deprecated in favor of [`irma server`](https://irma.app/docs/irma-server/), a subpackage of [`irmago`](https://github.com/privacybydesign/irmago).**

# IRMA API server

This is a server that sits between IRMA tokens such as the [IRMA app](https://github.com/privacybydesign/irma_mobile) on the one hand, and authorized service or identity providers on the other hand. It handles all IRMA-specific cryptographic details of issuing credentials and verifying disclosure proofs on behalf of the service or identity provider. It exposes a RESTful JSON API driven by JWTs for authentication.

The API that this server offers is described [here](https://credentials.github.io/protocols/irma-protocol). We offer a client of the API exposed by this server in the form of a javascript library, [irma_js](https://github.com/privacybydesign/irma_js), that you can use in your webpages to easily issue and verify credentials. The flow of the various interactions of these components in a typical IRMA session is shown [here](https://credentials.github.io/#irma-session-flow).

See below to run or build the server yourself. Alternatively, you can use our demo API server, which is setup to be very permissive (but only in the demo domain). It is hosted at `https://demo.irmacard.org/tomcat/irma_api_server/`, you can find its signing key [here](https://demo.irmacard.org/v2/data/pk.pem).

Note that this server requires Java 7 or Java 8.

# Running with Docker

The easiest way to get this server quickly up and running is using Docker.

First generate an JWT keypair that will be used by the API server to sign its responses:

    ./utils/docker/docker_keygen.sh

This will output a Docker command that will run the API server and set the JWT keys in environment variables. It will also show the public JWT key in PEM format. Be sure to  save both the run command and the JWT key someplace safe.

Now, run the container using the command generated from the script, for example:

    docker run -p 8088:8080 -e IRMA_API_CONF_BASE64_JWT_PUBLICKEY=exampleDoNotCopy -e IRMA_API_CONF_BASE64_JWT_PRIVATEKEY=exampleDoNotCopy privacybydesign/irma_api_server

The Docker container will bind to port 8088 on any interface, so the IRMA API Server is reachable at http://localhost:8088/api/v2.

By default, the API server in the container will allow unsigned verification and signature requests from all clients. Issue requests are blocked. This behaviour can be customized with environment variables (using '-e' flags of `docker run`). See [here](#config-via-environment-variables) for configuration of these environment variables.

## Testing and connecting to the Docker IRMA API Server

An example test service provider is included in the directory `utils/docker`:

    cd utils/docker
    npm install
    npm run testsp http://localhost:8088

This will show a QR code.

In order to make that QR code usable by the IRMA App, you'll need to make sure that the IRMA API server and the phone are on the same network (i.e. the Docker container should be reachable by the phone). This can be done by providing your local IP address to the npm testcommand. You can find and start test service provider with:

    npm run testsp http://YOUR_IP_ADDRESS:8088

# Configuring the server without Docker
Currently, the server expects all configuration files in a single directory. The location of this server can be configured by setting a environment variable called `IRMA_API_CONF`, for example,

    IRMA_API_CONF=/etc/irma_api_server gradle appRun

or

    IRMA_API_CONF=/etc/irma_api_server ./start.sh

depending if you are running a build or not. If this variable is left empty, then the server will try the following locations:
 1. `src/main/resources`
 2. `/etc/irma_api_server`
 3. `C:\irma_api_server`
 4. `~/irma_api_server`

The main configuration file is a json file called `config.json`. In `src/main/resources` a sample configuration file called `config.SAMPLE.json` is included, showing all options, their defaults, and what they mean.

The server always looks for `config.json` and the `irma_configuration` folder (and in fact all other configuration files as well) in the same place. The `IRMA_API_CONF` environment variable can be used to instruct the server to look for (all) its configuration in a place of your choosing (such as `/etc/irma_api_server`). So if you're using IRMA_API_CONF in order to point the server to `/etc/irma_api_server`, then you should put your `irma_configuration` folder there as well.  

## irma_configuration

All credential descriptions, issuer public keys and possibly private keys - that is, the *scheme manager* information - are expected in a subdirectory called `irma_configuration` within the configuration directory. There are several options:

* You can use our [`irma-demo`](https://github.com/privacybydesign/irma-demo-schememanager) scheme manager (which includes issuer private keys) for experimenting,
* You can use our [`pbdf`](https://github.com/privacybydesign/pbdf-schememanager) if you want to verify attributes issued by the [Privacy by Design Foundation](https://privacybydesign.foundation/issuance),
* you can create your own scheme manager containing your own issuers and credential types.

For example, in the first case, you would `cd` to your configuration directory, and do

    mkdir irma_configuration 2>/dev/null
    cd irma_configuration
    git clone https://github.com/privacybydesign/irma-demo-schememanager irma-demo

For more information, see the [README.md of the `irma-demo` scheme manager](https://github.com/privacybydesign/irma-demo-schememanager).

## Ports

You can change the ports on which a build of the server listens as follows:

    ./start.sh --runnerArg="httpPort=8080" --runnerArg="httpsPort=8443"

If you want to change the ports when using `gradle appRun` to start the server, you'll have to modify `build.gradle`.

## JWT keys

The server uses [JSON web tokens (JWT's)](https://en.wikipedia.org/wiki/JSON_Web_Token) for verifying the authenticity of incoming requests and for signing its output, in the case of verification. Before you can use the server, you need to set up some of the public and private keys for this. For this we have included a bash script `keygen.sh`, that uses the `openssl` command line tool. All keys must be in the DER format. In more detail:

 * `sk.der` in the configuration path is used to sign the final message to the service provider in a verification session. This can easily be generated by executing `utils/keygen.sh` (This will also generate the corresponding public key `pk.der`, which is not needed by the server, except when running unit tests.)
 * Identity and service providers must send their requests to the server in the form of JSON web tokens. Thus the server needs to know the public keys of all authorized service and/or identity providers. These are also stored in `issuers/` and `verifiers/` in the configuration path; see the configuration file for details.

Neither `utils/keygen.sh` nor `utils/preparetest.sh` will overwrite existing files.

## Config via environment variables

All config entries in `config.json`, as well as all the jwt keys (i.e. sk/pk.der) can also be defined as environment variables, which can be passed to a Docker container. In this way, `irma_configuration` is the only extra directory/set of files that is needed to run the server. All entries in `config.json` can be 'converted' to an environment variable by converting the entry to upper case and prepending it with `IRMA_API_CONF_`. For instance the config entry `"enable_verification": true,`, would be set with an environment variable as follows:

    export IRMA_API_CONF_ENABLE_VERIFICATION="true"

Config entries that are set via an environment variable always take priority over entries in the config file. For the config entries that require a json list (i.e. the entry `authorized_idps`), you can use raw json as a value for the environment variable.

JWT keys can also be set via environment variables, but since these key files are binary, they first must be converted to base64 in order to be stored in an environment variable. To store the `irma_api_server` jwt private key in an environment variable, you should use the following set of commands:

    cat sk.der | base64 -w0
    export IRMA_API_CONF_BASE64_JWT_PRIVATEKEY="<OUTPUT OF COMMAND ABOVE>"

Public keys for issuers/verifiers can also be set via environment variables. If you want for instance to set the key for the issuer 'MijnOverheid' (file: issuers/MijnOverheid.der), you can use the following environment variable/set of commands:

    cat issuers/MijnOverheid.der | base64 -w0
    export IRMA_API_CONF_BASE64_JWT_ISSUERS_MIJNOVERHEID="<OUTPUT OF COMMAND ABOVE>"

Public keyshare server keys from scheme managers can be set in the following way (example for pbdf scheme manager):

    cat pbdf-kss.der | base64 -w0
    export IRMA_API_CONF_BASE64_KSS_PBDF="<OUTPUT OF COMMAND ABOVE>"

Like with the config entries, keys that are set via environment variables are prioritized over keys that are located in files.

# Running and building the server

The gradle build file should take care the dependencies. To run the server in development mode simply call:

    gradle appRun

You can produce a .war file suitable for Tomcat 7 by running

    gradle war

Alternatively, you can build the server, resulting in a standalone package that depends only on Java, as follows:

    gradle buildProduct

The resulting package will then be stored in `build/output/irma_api_server` and can be started with `start.sh`. ***NOTE***: before runnung `gradle war` or `buildProduct`, be sure to run `git submodule update --init` first! This fetches the [IRMA configuration and keys](https://github.com/privacybydesign/irma-demo-schememanager) that are used for the unit tests, which are automatically performed by these two gradle commands.

# Testing

You can run the included unit tests by running `gradle test`; in this case `src/test/resources` will always be used as the configuration directory (which comes with its own configuration files for this purpose, as well as `irma_configuration` as a git submodule. Be sure to run `git submodule update --init`!).

A test service provider and identity provider, written in node.js, is included; see `utils/testsp.js` and `utils/testip.js` respectively. If you haven't done so already, you should install the dependencies (assuming you already have node.js installed):

    npm install qrcode-terminal request jsonwebtoken fs

Furthermore, you should run the `utils/preparetestjs.sh` script to prepare testing keys (which will be placed in `src/main/resources`), and make sure that you enable these test keys in your `config.json` in `src/main/resources`, for example. Using `config.sample-demo.json` as the configuration file should do the trick.

After this you can run it using:

    node utils/testsp.js http://<SERVER>:8088 [configuration_dir]

where `<SERVER>` refers to the IP address or hostname of your running `irma_api_server`, and where the optional second argument specifies the configuration directory in which the script is to find the JWT keys (if absent, `src/main/resources` is assumed). Make sure you use an address that the IRMA app can also reach (we usually use a local ip address for testing).

For more sophisticated examples, see [irma_js](https://github.com/privacybydesign/irma_js).
