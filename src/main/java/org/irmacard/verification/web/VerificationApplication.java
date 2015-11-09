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

package org.irmacard.verification.web;

import java.net.URI;
import java.net.URISyntaxException;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;

@ApplicationPath("/")
public class VerificationApplication extends ResourceConfig {
    public VerificationApplication() {
        // register Gson
        register(GsonJerseyProvider.class);

        // register enrollment application
        register(VerificationResource.class);

        // register session state
        register(new VerificationSessionsBinder());

        // Setup Core location for IRMA
        URI CORE_LOCATION;
        // TODO this try catch system is not very elegant, make a function to
        // test if the stores are initialized
        try {
            DescriptionStore.getInstance();
            IdemixKeyStore.getInstance();
        } catch (InfoException e) {
            // Not initialized, try now
            try {
                CORE_LOCATION = VerificationApplication.class.getClassLoader().getResource("/irma_configuration/").toURI();
                DescriptionStore.setCoreLocation(CORE_LOCATION);
                DescriptionStore.getInstance();
                IdemixKeyStore.setCoreLocation(CORE_LOCATION);
                IdemixKeyStore.getInstance();
            } catch (URISyntaxException|InfoException e2) {
                e2.printStackTrace();
                throw new RuntimeException(e2);
            }
        }
    }
}
