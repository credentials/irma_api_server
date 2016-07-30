/*
 * VerificationApplication.java
 *
 * Copyright (c) 2015, Sietse Ringers, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.api.web;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.info.*;

@ApplicationPath("/")
public class ApiApplication extends ResourceConfig {
    private static URI confPath;

    public ApiApplication() {
        System.out.println("Using configuration path: " + getConfigurationPath().toString());

        // register Gson
        register(GsonJerseyProvider.class);

        // register exception handler, for converting and then returning exceptions as JSON output
        register(ApiExceptionMapper.class);

        // register verification application
        register(VerificationResource.class);

        // register issuing application, if applicable
        if (ApiConfiguration.getInstance().isIssuingEnabled()) {
            System.out.println("Enabling issuing");
            register(IssueResource.class);
        } else {
            System.out.println("Disabling issuing");
        }

        // register CORS filter
        register(CORSResponseFilter.class);

        try {
            URI CORE_LOCATION = getConfigurationPath().resolve("irma_configuration/");
            DescriptionStore.initialize(new DescriptionStoreDeserializer(CORE_LOCATION));
            IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(CORE_LOCATION));
        } catch (InfoException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns true if the specified path is a valid configuration directory. Currently a directory
     * is considered a valid configuration directory if it contains a subdir called irma_configuration.
     */
    public static boolean isConfDirectory(URI candidate) {
        if (candidate == null)
            return false;
        return new File(candidate.resolve("irma_configuration/")).isDirectory();
    }

    /**
     * Depending on if we're running tests according to {@link ApiConfiguration#testing},
     * returns either src/main/resources or src/test/resources, if it contains irma_configuration.
     * @return URI to src/main/resources or src/test/resources if it contains irma_configuration, null otherwise
     */
    public static URI getResourcesConfPath() throws URISyntaxException {
        // The only way to actually get the resource folder, as opposed to the classes folder,
        // seems to be to ask for an existing file or directory within the resources. That is,
        // ApiApplication.class.getClassLoader().getResource("/") or variants thereof
        // give an incorrect path. This is why we must treat this as a separate case.
        // Also, to get src/main/resources/irma_configuration one must apparently include a leading
        // slash, but not when fetching src/test/resources/irma_configuration :(

        URL url = ApiApplication.class.getClassLoader().getResource(
                (ApiConfiguration.testing ? "" : "/") + "irma_configuration/");
        if (url != null) // Construct an URI of the parent path
            return  new URI("file://" + new File(url.getPath()).getParent() + "/");
        else
            return null;
    }

    /**
     * If a path was set in the IRMA_CONF_PATH environment variable, return it
     */
    public static URI getEnvVariableConfPath() throws URISyntaxException {
        String envPath = System.getenv("IRMA_CONF_PATH");
        if (envPath == null || envPath.length() == 0)
            return null;

        if (!envPath.startsWith("file://"))
            envPath = "file://" + envPath;
        if (!envPath.endsWith("/"))
            envPath += "/";

        return new URI(envPath);
    }

    /**
     * Get the configuration directory.
     * @throws IllegalStateException If no suitable configuration directory was found
     * @throws IllegalArgumentException If the path from the IRMA_CONF_PATH environment variable was
     *                                  not a valid path
     */
    public static URI getConfigurationPath() throws IllegalStateException, IllegalArgumentException {
        if (confPath != null)
            return confPath;

        try {
            URI resourcesCandidate = getResourcesConfPath();

            // If we're running unit tests, only accept src/test/resources
            if (ApiConfiguration.testing) {
                if (resourcesCandidate != null) {
                    confPath = resourcesCandidate;
                    return confPath;
                }
                else
                    throw new IllegalStateException("irma_configuration not found in src/test/resources. " +
                            "(Have you run `git submodule init && git submodule update`?)");
            }

            // If we're here, we're not running unit tests.
            // If a path was given in the IRMA_CONF_PATH environment variable, prefer it
            URI envCandidate = getEnvVariableConfPath();
            if (envCandidate != null) {
                if (isConfDirectory(envCandidate)) {
                    confPath = envCandidate;
                    return confPath;
                } else {
                    // If the user specified an incorrect path (s)he will want to know, so bail out here
                    throw new IllegalArgumentException("Specified path in IRMA_API_CONF is not " +
                            "a valid configuration directory");
                }
            }

            // See if a number of other fixed candidates are suitable
            ArrayList<URI> candidates = new ArrayList<>(4);
            candidates.add(resourcesCandidate);
            candidates.add(new URI("file:///etc/irma_api_server/"));
            candidates.add(new URI("file:///C:/irma_api_server/"));
            candidates.add(new File(System.getProperty("user.home")).toURI().resolve("irma_api_server/"));

            for (URI candidate : candidates) {
                if (isConfDirectory(candidate)) {
                    confPath = candidate;
                    return confPath;
                }
            }

            throw new IllegalStateException("irma_configuration not found in any of the possible " +
                    "configuration directories. See README.md for more information.");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
