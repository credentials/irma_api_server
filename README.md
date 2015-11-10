# Running the server

The gradle build file should take care of most of the dependencies. However, `irma_verification_common` is not yet available in the central IRMA repository, so you'll have to manually download and install it. To run the server in development mode simply call:

    gradle jettyRun

it is set up in such a way that it will automatically reload recompile class files. If your IDE already uses gradle to compile them this should work out of the box. Otherwise, simply call

    gradle javaCompile

and your app will be reloaded. Note that this is a lot faster than simply restarting the Jetty container.

# Testing with cURL

To make a GET request on a resource:

    curl -i -H "Accept: application/json" http://localhost:8080/irma_verification_server/api/hello/json

To make a POST request on a resource:

    curl -X POST -H "Content-Type: application/json" -d '{"a": 5.0,"b": -22.0}' http://localhost:8080/irma_verification_server_jersey/api/hello/json

