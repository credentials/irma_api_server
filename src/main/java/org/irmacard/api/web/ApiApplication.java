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

import org.glassfish.jersey.server.ResourceConfig;
import org.irmacard.api.web.resources.IssueResource;
import org.irmacard.api.web.resources.SignatureResource;
import org.irmacard.api.web.resources.VerificationResource;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.DescriptionStoreDeserializer;
import org.irmacard.credentials.info.InfoException;

import javax.ws.rs.ApplicationPath;
import java.net.URI;

@ApplicationPath("/")
public class ApiApplication extends ResourceConfig {
    public ApiApplication() {
        System.out.println("Using configuration path: " + ApiConfiguration.getConfigurationPath().toString());

        // register Gson
        register(GsonJerseyProvider.class);

        // register exception handler, for converting and then returning exceptions as JSON output
        register(ApiExceptionMapper.class);

        // register verification application
        register(VerificationResource.class);

        // register signature application
        register(SignatureResource.class);

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
            URI CORE_LOCATION = ApiConfiguration.getConfigurationPath().resolve("irma_configuration/");
            DescriptionStore.initialize(new DescriptionStoreDeserializer(CORE_LOCATION));
            IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(CORE_LOCATION));
        } catch (InfoException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
