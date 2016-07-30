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

    public static URI getConfigurationPath() throws IllegalStateException {
        if (confPath != null)
            return confPath;

        try {
            URI[] candidates = {
                    new URI("file:///etc/irma_api_server/"),
                    new URI("file:///C:/irma_api_server/"),
                    new File(System.getProperty("user.home")).toURI().resolve("irma_api_server/")
            };

            // The only way to actually get the resource folder, as opposed to the classes folder,
            // seems to be to ask for an existing file or directory within the resources. That is,
            // ApiApplication.class.getClassLoader().getResource("/") or variants thereof
            // give an incorrect path. This is why we must treat this as a separate case.
            // Also, to get src/main/resources/irma_configuration one must apparently include a leading
            // slash, but not when fetching src/test/resources/irma_configuration :(

            URI resourcesCandidate = null;
            URL url = ApiApplication.class.getClassLoader().getResource(
                    (ApiConfiguration.testing ? "" : "/") + "irma_configuration/");
            if (url != null) // Construct an URI of the parent path
                resourcesCandidate = new URI("file://" + new File(url.getPath()).getParent() + "/");

            if (resourcesCandidate != null) {
                confPath = new URI("file://" + new File(url.getPath()).getParent() + "/");
                return confPath;
            }

            // If we are running tests, only accept src/test/resources
            if (ApiConfiguration.testing)
                throw new IllegalStateException("irma_configuration not found in src/test/resources. " +
                        "(Have you run `git submodule init && git submodule update`?)");

            // Otherwise, check the other candidates
            for (URI candidate : candidates) {
                if (new File(candidate.resolve("irma_configuration/")).isDirectory()) {
                    confPath = candidate;
                    return confPath;
                }
            }

            throw new IllegalStateException("irma_configuration not found in " +
                    "/etc/irma_api_server or src/main/resources. See README.md for more information.");
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}
