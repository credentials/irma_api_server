/*
 * VerificationResource.java
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

package org.irmacard.api.web.resources;


import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.JwtSessionRequest;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.disclosure.ServiceProviderRequest;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.sessions.IrmaSession.Status;
import org.irmacard.api.web.sessions.Sessions;
import org.irmacard.api.web.sessions.VerificationSession;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.util.Calendar;


@Path("verification")
public class VerificationResource extends BaseResource
        <DisclosureProofRequest, ServiceProviderRequest, VerificationSession> {
    private static Logger logger = LoggerFactory.getLogger(VerificationResource.class);
    private static final int DEFAULT_TOKEN_VALIDITY = 60 * 60; // 1 hour

    @Inject
    public VerificationResource() {
        super(Action.DISCLOSING, Sessions.getVerificationSessions());
    }

    @POST
    @Consumes({MediaType.TEXT_PLAIN,MediaType.APPLICATION_JSON})
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public ClientQr newSession(String jwt) {
        return super.newSession(jwt);
    }

    @GET @Path("/{sessiontoken}")
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public DisclosureProofRequest get(@PathParam("sessiontoken") String sessiontoken) {
        return super.get(sessiontoken);
    }

    @GET @Path("/{sessiontoken}/jwt")
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public JwtSessionRequest getJwt(@PathParam("sessiontoken") String sessiontoken, @HeaderParam("X-IRMA-ProtocolVersion") String version) {
       return super.getJwt(sessiontoken, version);
    }

    @GET @Path("/{sessiontoken}/status")
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public Status getStatus(@PathParam("sessiontoken") String sessiontoken) {
        return super.getStatus(sessiontoken);
    }

    @DELETE @Path("/{sessiontoken}")
    @Override
    public void delete(@PathParam("sessiontoken") String sessiontoken) {
        super.delete(sessiontoken);
    }

    @Override
    protected ClientQr create(ServiceProviderRequest spRequest, String verifier, String jwt) {
        DisclosureProofRequest request = spRequest.getRequest();

        if (request == null || request.getContent() == null || request.getContent().size() == 0)
            throw new ApiException(ApiError.MALFORMED_VERIFIER_REQUEST);

        // Check if the requested attributes match the DescriptionStore
        if (!request.attributesMatchStore())
            throw new ApiException(ApiError.ATTRIBUTES_WRONG);

        // Check if this SP is authorized to verify these attributes
        for (AttributeDisjunction disjunction : request.getContent())
            for (AttributeIdentifier identifier : disjunction)
                if (!ApiConfiguration.getInstance().canVerifyAttribute(verifier, identifier))
                    throw new ApiException(ApiError.UNAUTHORIZED, identifier.toString());

        if (spRequest.getValidity() == 0)
            spRequest.setValidity(DEFAULT_TOKEN_VALIDITY);

        VerificationSession session = new VerificationSession();
        return super.create(session, spRequest, jwt);
    }

    @POST @Path("/{sessiontoken}/proofs")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public DisclosureProofResult.Status proofs(ProofList proofs, @PathParam("sessiontoken") String sessiontoken)
            throws InfoException {
        VerificationSession session = sessions.getNonNullSession(sessiontoken);

        DisclosureProofResult result;
        try {
            proofs.populatePublicKeyArray();
            result = session.getRequest().verify(proofs);
        } catch (Exception e) {
            // Everything in the verification has to be exactly right; if not, we don't accept the proofs as valid
            e.printStackTrace();
            result = new DisclosureProofResult();
            result.setStatus(DisclosureProofResult.Status.INVALID);
        }
        session.setResult(result);

        logger.info("Received proofs, token: " + sessiontoken);

        // If a callback url is supplied, call it
        if (session.getClientRequest().getCallbackUrl() != null) {
            String callbackUrl = session.getClientRequest().getCallbackUrl() + "/" + sessiontoken;
            logger.info("Posting proof to: " + callbackUrl);

            try {
                sendProofResult(new URL(callbackUrl), gettoken(sessiontoken));
            } catch (MalformedURLException|KeyManagementException e) {
                e.printStackTrace();
            }
        }

        return result.getStatus();
    }

    @GET @Path("/{sessiontoken}/getunsignedproof")
    @Produces(MediaType.APPLICATION_JSON)
    public DisclosureProofResult getproof(@PathParam("sessiontoken") String sessiontoken) {
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        DisclosureProofResult result = session.getResult();

        if (result == null) {
            result = new DisclosureProofResult();
            result.setStatus(DisclosureProofResult.Status.WAITING);
        } else {
            session.close();
        }

        result.setServiceProviderData(session.getClientRequest().getData());
        return result;
    }

    // TODO: This seems to also return (signed) data even if the proof does not
    // verify, maybe we want to refuse this method if that is the case, need to
    // change workflow to allow this.
    @GET @Path("/{sessiontoken}/getproof")
    @Produces(MediaType.TEXT_PLAIN)
    public String gettoken(@PathParam("sessiontoken") String sessiontoken) throws KeyManagementException {
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        DisclosureProofResult result = getproof(sessiontoken);

        Calendar now = Calendar.getInstance();
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.SECOND, session.getClientRequest().getValidity());

        JwtBuilder builder = Jwts.builder()
                .setClaims(result.getAsMap())
                .setIssuedAt(now.getTime())
                .setExpiration(expiry.getTime())
                .setSubject("disclosure_result");

        String jwt_issuer = ApiConfiguration.getInstance().getJwtIssuer();
        if (jwt_issuer != null)
            builder = builder.setIssuer(jwt_issuer);

        return builder
                .signWith(ApiConfiguration.getInstance().getJwtAlgorithm(),
                        ApiConfiguration.getInstance().getJwtPrivateKey())
                .compact();
    }

    // TODO: move to some kind of 'util class'?
    private static void sendProofResult(final URL url, String jwt) {
        final HttpTransport transport = new NetHttpTransport.Builder().build();
        final HttpContent content = new ByteArrayContent("text/plain", jwt.getBytes());

        new Thread() {
            @Override
            public void run() {
                try {
                    HttpRequest proofResultRequest = transport.createRequestFactory().buildPostRequest(new GenericUrl(url), content);
                    HttpResponse response = proofResultRequest.execute();
                    logger.info("Proof sent to callbackURL");
                } catch (Exception e) {
                    logger.error("Sending proof failed: {}", e.getMessage());
                    e.printStackTrace();
                }

            }
        }.start();
    }
}
