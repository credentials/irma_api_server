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

import io.jsonwebtoken.Jwts;
import org.irmacard.api.common.*;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.web.IrmaSession.Status;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

import java.security.KeyManagementException;
import java.util.Calendar;


@Path("verification")
public class VerificationResource {
    private Sessions<VerificationSession> sessions = Sessions.getVerificationSessions();

    private static final int DEFAULT_TOKEN_VALIDITY = 60 * 60; // 1 hour

    @Inject
    public VerificationResource() {}

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public ClientQr create(ServiceProviderRequest spRequest) {
        DisclosureProofRequest request = spRequest.getRequest();

        if (request.getContent() == null || request.getContent().size() == 0)
            throw new ApiException(ApiError.MALFORMED_VERIFIER_REQUEST);

        if (spRequest.getValidity() == 0)
            spRequest.setValidity(DEFAULT_TOKEN_VALIDITY);

        request.setNonceAndContext();

        String token = Sessions.generateSessionToken();
        VerificationSession session = new VerificationSession(token, spRequest);
        sessions.addSession(session);

        System.out.println("Received session, token: " + token);
        System.out.println(request.toString());

        return new ClientQr("2.0", token);
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
    @Path("/{sessiontoken}/status")
    @Produces(MediaType.APPLICATION_JSON)
    public Status getStatus(
            @PathParam("sessiontoken") String sessiontoken) {
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        Status status = session.getStatus();

        // Remove the session if this session is cancelled
        if (status == Status.CANCELLED) {
            session.close();
            sessions.remove(session);
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

            // TODO: determine the exact reason for failure and report back
            result.setStatus(DisclosureProofResult.Status.INVALID);
        }
        session.setResult(result);

        System.out.println("Received proofs, token: " + sessiontoken);
        System.out.println(GsonUtil.getGson().toJson(result));

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
            sessions.remove(session);
        }

        result.setServiceProviderData(session.getServiceProviderRequest().getServiceProviderData());
        return result;
    }

    @GET
    @Path("/{sessiontoken}/getproof")
    @Produces(MediaType.TEXT_PLAIN)
    public String gettoken(@PathParam("sessiontoken") String sessiontoken) throws KeyManagementException {
        System.out.println("Retrieving signed proof");
        VerificationSession session = sessions.getNonNullSession(sessiontoken);
        DisclosureProofResult result = getproof(sessiontoken);

        // Do not return a signed token if the proof is invalid
        if (result.getStatus() != DisclosureProofResult.Status.VALID) {
            System.out.println("Returning failed proof");
            throw new ApiException(ApiError.INVALID_PROOFS);
        }

        Calendar now = Calendar.getInstance();
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.SECOND, session.getServiceProviderRequest().getValidity());

        return Jwts.builder()
                .setClaims(result.getAsMap())
                .setIssuedAt(now.getTime())
                .setExpiration(expiry.getTime())
                .setSubject("disclosure_result")
                .signWith(ApiConfiguration.getInstance().getJwtAlgorithm(),
                        ApiConfiguration.getInstance().getJwtPrivateKey())
                .compact();
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
            // TODO: if the poll never happens, the session is never removed
            if (session.isStatusSocketConnected()) {
                session.close();
                sessions.remove(session);
            }
        } else {
            // In all other cases INITIALIZED, CANCELLED, DONE all parties
            // are already informed, we can close the session

            session.close();
            sessions.remove(session);
        }
    }
}
