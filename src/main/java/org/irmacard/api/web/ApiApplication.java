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
import org.irmacard.api.common.ProtocolVersion;
import org.irmacard.api.web.resources.IssueResource;
import org.irmacard.api.web.resources.SignatureResource;
import org.irmacard.api.web.resources.VerificationResource;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.updater.Updater;
import org.irmacard.credentials.info.DescriptionStoreDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.Path;
import java.net.URI;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

@ApplicationPath("/")
public class ApiApplication extends ResourceConfig {
    private static Logger logger = LoggerFactory.getLogger(ApiApplication.class);

    public static final ProtocolVersion minVersion = new ProtocolVersion("2.0");
    public static final ProtocolVersion maxVersion = new ProtocolVersion("2.4");

    public ApiApplication() {
        // register Gson
        register(GsonJerseyProvider.class);

        // register exception handler, for converting and then returning exceptions as JSON output
        register(ApiExceptionMapper.class);

        Class[] resources = {
                IssueResource.class,
                VerificationResource.class,
                SignatureResource.class
        };

        for (Class resource : resources) {
            // register verification application
            if ( ApiConfiguration.getInstance().isEnabled(resource) && (resource != SignatureResource.class || GoBridge.isEnabled()) ) {
                logger.warn("Enabling " + resource.getSimpleName()
                        + " at /" + ((Path)resource.getAnnotation(Path.class)).value());
                register(resource);
            } else {
                logger.warn("Disabling " + resource.getSimpleName());
            }
        }

        // register CORS filter
        register(CORSResponseFilter.class);

        ApiConfiguration conf = ApiConfiguration.getInstance();
        loadOrUpdateIrmaConfiguration(true);

        if (conf.schemeManager_update_uri != null) {
            BackgroundJobManager.getScheduler().scheduleAtFixedRate(new Runnable() {
                @Override public void run() {
                    loadOrUpdateIrmaConfiguration(false);
                }
            }, 1, 1, TimeUnit.HOURS);
        }

        // Enable the Historian class, if an events webhook uri is set.
        if (conf.events_webhook_uri != null) {
            Historian.getInstance().enable(
                    conf.events_webhook_uri,
                    conf.events_webhook_authorizationToken);
        }
    }

    private void loadOrUpdateIrmaConfiguration(boolean initial) {
        ApiConfiguration conf = ApiConfiguration.getInstance();
        URI CORE_LOCATION = ApiConfiguration.getConfigurationDirectory().resolve("irma_configuration/");
        boolean updated = false;

        if (conf.schemeManager_update_uri != null) {
            logger.info("Updating irma_configuration from {} ...",
                    conf.schemeManager_update_uri);
            try {
                updated = Updater.update(
                        conf.schemeManager_update_uri,
                        Paths.get(CORE_LOCATION).toString(),
                        conf.getSchemeManagerPublicKeyString());
            } catch(Exception e) {
                logger.error("Update failed:", e);
            }
        }

        try {
            if (initial || updated) {
                DescriptionStore.initialize(new DescriptionStoreDeserializer(CORE_LOCATION));
                IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(CORE_LOCATION));
            }
        } catch (Exception e) {
            logger.error("Store initialization failed:", e);
        }
    }
}
