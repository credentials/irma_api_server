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

package org.irmacard.verification.web;

import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.verification.common.DisclosureProofRequest;
import org.irmacard.verification.common.DisclosureProofResult;
import org.irmacard.verification.common.ServiceProviderRequest;
import org.irmacard.verification.common.util.GsonUtil;
import org.irmacard.verification.web.exceptions.InputInvalidException;

import org.apache.commons.codec.binary.Base64;
import org.irmacard.verification.web.exceptions.SessionUnknownException;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

import java.math.BigInteger;
import java.security.SecureRandom;


@Path("v1")
public class VerificationResource {
    private SecureRandom rnd;

    @Inject
    private VerificationSessions sessions;

    private static final int SESSION_TOKEN_LENGTH = 33;

    @Inject
    public VerificationResource() {
        rnd = new SecureRandom();
    }

    @POST
    @Path("/create")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String create(ServiceProviderRequest spRequest) {
        DisclosureProofRequest request = spRequest.getRequest();

        if (!request.isSimple())
            throw new InputInvalidException("Non-simple requests are not yet supported by this server");

        request.setNonce(DisclosureProofRequest.generateNonce());
        if (request.getContext() == null || request.getContext().equals(BigInteger.ZERO))
            request.setContext(Crypto.sha256Hash(request.toString(false).getBytes()));

        String token = generateSessionToken();
        VerificationSession session = new VerificationSession(token, spRequest);
        sessions.addSession(session);

        System.out.println("Received session, token: " + token);
        System.out.println(request.toString());

        return token;
    }

    @GET
    @Path("/{sessiontoken}")
    @Produces(MediaType.APPLICATION_JSON)
    public DisclosureProofRequest get(@PathParam("sessiontoken") String sessiontoken) {
        System.out.println("Received get, token: " + sessiontoken);

        return getSession(sessiontoken).getRequest();
    }


    @POST
    @Path("/{sessiontoken}/proof")
    @Consumes(MediaType.APPLICATION_JSON)
    public void proof(ProofD proof, @PathParam("sessiontoken") String sessiontoken) throws InfoException {
        VerificationSession session = getSession(sessiontoken);
        session.setProof(proof);

        DisclosureProofResult result = session.getRequest().verify(proof);
        session.setResult(result);

        System.out.println("Received proof, token: " + sessiontoken);
        System.out.println(GsonUtil.getGson().toJson(result));
    }

    @GET
    @Path("/{sessiontoken}/getproof")
    @Produces(MediaType.APPLICATION_JSON)
    public DisclosureProofResult getproof(@PathParam("sessiontoken") String sessiontoken) throws InfoException {
        VerificationSession session = getSession(sessiontoken);
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

    @DELETE
    @Path("/{sessiontoken}")
    public void delete(@PathParam("sessiontoken") String sessiontoken) {
        VerificationSession session = getSession(sessiontoken);

        System.out.println("Received delete, token: " + sessiontoken);
        sessions.remove(session);
    }

    /**
     * Either returns a valid, non-null session associated to the specified token, or throws an exception.
     * @throws InputInvalidException if the token is null or ""
     * @throws SessionUnknownException if there is no session corresponding to the token
     */
    private VerificationSession getSession(String token) throws InputInvalidException, SessionUnknownException {
        if (token == null || token.equals(""))
            throw new InputInvalidException("Supply a valid session token");

        VerificationSession session = sessions.getSession(token);
        if (session == null)
            throw new SessionUnknownException();

        return session;
    }

    /**
     * A random session token. Returns a base64 encoded string representing the
     * session token. The characters '+' and '/' are removed from this
     * representation.
     *
     * @return the random session token
     */
    private String generateSessionToken() {
        byte[] token = new byte[SESSION_TOKEN_LENGTH];
        rnd.nextBytes(token);
        String strtoken = Base64.encodeBase64String(token);
        return strtoken.replace("+", "").replace("/", "");
    }
}