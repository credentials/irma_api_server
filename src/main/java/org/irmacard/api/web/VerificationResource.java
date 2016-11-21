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

package org.irmacard.api.web;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import io.jsonwebtoken.*;
import org.irmacard.api.common.*;
import org.irmacard.api.common.JwtParser;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.web.sessions.IrmaSession.Status;
import org.irmacard.api.web.sessions.Sessions;
import org.irmacard.api.web.sessions.VerificationSession;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.InfoException;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyManagementException;
import java.util.Calendar;


@Path("verification")
public class VerificationResource {
    private Sessions<VerificationSession> sessions = Sessions.getVerificationSessions();

    private static final int DEFAULT_TOKEN_VALIDITY = 60 * 60; // 1 hour

    @Inject
    public VerificationResource() {}

    @POST
    @Consumes({MediaType.TEXT_PLAIN,MediaType.APPLICATION_JSON})
    @Produces(MediaType.APPLICATION_JSON)
    public ClientQr newSession(String jwt) {
        if (ApiConfiguration.getInstance().isHotReloadEnabled())
            ApiConfiguration.load();

        JwtParser<ServiceProviderRequest> parser = new JwtParser<>(ServiceProviderRequest.class,
                ApiConfiguration.getInstance().allowUnsignedVerificationRequests(),
                ApiConfiguration.getInstance().getMaxJwtAge());

        parser.setKeyResolver(new SigningKeyResolverAdapter() {
            @Override public Key resolveSigningKey(JwsHeader header, Claims claims) {
                String keyId = (String) header.get("kid");
                if (keyId == null)
                    keyId = claims.getIssuer();
                return ApiConfiguration.getInstance().getClientPublicKey("verifiers", keyId);
            }
        });

        ServiceProviderRequest request = parser.parseJwt(jwt).getPayload();
        return create(request, parser.getJwtIssuer(), jwt);
    }

    public ClientQr create(ServiceProviderRequest spRequest, String verifier, String jwt) {
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
        if (spRequest.getTimeout() == 0)
            spRequest.setTimeout(ApiConfiguration.getInstance().getTokenGetTimeout());

        request.setNonceAndContext();

        VerificationSession session = new VerificationSession(spRequest);
        session.setJwt(jwt);
        String token = session.getSessionToken();
        sessions.addSession(session);

        System.out.println("Received session, token: " + token);
        System.out.println(request.toString());

        return new ClientQr("2.0", "2.1", token);
    }

    @GET
    @Path("/{sessiontoken}")
    @Produces(MediaType.APPLICATION_JSON)
    public DisclosureProofRequest get(@PathParam("sessiontoken") String sessiontoken) {
        System.out.println("Received get, token: " + sessiontoken);
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        session.setStatusConnected();

        return session.getRequest();
    }

    @GET
    @Path("/{sessiontoken}/jwt")
    @Produces(MediaType.APPLICATION_JSON)
    public JwtSessionRequest getJwt(@PathParam("sessiontoken") String sessiontoken) {
        System.out.println("Received get, token: " + sessiontoken);
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        session.setStatusConnected();

        DisclosureProofRequest request = session.getRequest();

        return new JwtSessionRequest(session.getJwt(), request.getNonce(), request.getContext());
    }

    @GET
    @Path("/{sessiontoken}/status")
    @Produces(MediaType.APPLICATION_JSON)
    public Status getStatus(
            @PathParam("sessiontoken") String sessiontoken) {
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        Status status = session.getStatus();

        // Remove the session if this session is cancelled
        if (status == Status.CANCELLED) {
            session.close();
        }

        return status;
    }

    @POST
    @Path("/{sessiontoken}/proofs")
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

        System.out.println("Received proofs, token: " + sessiontoken);

        // If a callback url is supplied, call it
        if (session.getClientRequest().getCallbackUrl() != null) {
            String callbackUrl = session.getClientRequest().getCallbackUrl() + "/" + sessiontoken;
            System.out.println("Posting proof to: " + callbackUrl);

            try {
                sendProofResult(new URL(callbackUrl), gettoken(sessiontoken));
            } catch (MalformedURLException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
        }

        return result.getStatus();
    }

    @GET
    @Path("/{sessiontoken}/getunsignedproof")
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
    @GET
    @Path("/{sessiontoken}/getproof")
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
                    System.out.println("Proof sent to callbackURL, result: " + new BufferedReader(new InputStreamReader(response.getContent())).readLine());
                } catch (HttpResponseException e) {
                    System.out.println("Sending proof failed!");
                    System.out.println(e.getMessage());
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }.start();
    }

    @DELETE
    @Path("/{sessiontoken}")
    public void delete(@PathParam("sessiontoken") String sessiontoken) {
        VerificationSession session = sessions.getNonNullSession(sessiontoken);

        System.out.println("Received delete, token: " + sessiontoken);
        if (session.getStatus() == Status.CONNECTED) {
            // We have connected clients, we need to inform listeners of cancel
            session.setStatusCancelled();

            // If status socket is still active then the update has been sent, so we
            // can remove the session immediately. Otherwise we wait until the
            // status has been polled.
            if (session.isStatusSocketConnected()) {
                session.close();
            }
        } else {
            // In all other cases INITIALIZED, CANCELLED, DONE all parties
            // are already informed, we can close the session
            session.close();
        }
    }
}
