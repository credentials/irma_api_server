/*
 * SignatureResource.java
 *
 * Copyright (c) 2016, Koen van Ingen, Radboud University
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

import org.irmacard.api.common.AttributeBasedSignature;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.JwtSessionRequest;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.signatures.SignatureClientRequest;
import org.irmacard.api.common.signatures.SignatureProofRequest;
import org.irmacard.api.common.signatures.SignatureProofResult;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.sessions.IrmaSession.Status;
import org.irmacard.api.web.sessions.Sessions;
import org.irmacard.api.web.sessions.SignatureSession;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.xml.bind.DatatypeConverter;
import java.util.Calendar;
import java.util.Date;

@Path("signature")
public class SignatureResource extends BaseResource
		<SignatureProofRequest, SignatureClientRequest, SignatureSession>{
	private static final int DEFAULT_TOKEN_VALIDITY = 60 * 60; // 1 hour

	@Inject
	public SignatureResource() {
		super(Action.SIGNING, Sessions.getSignatureSessions());
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
	public SignatureProofRequest get(@PathParam("sessiontoken") String sessiontoken) {
		return super.get(sessiontoken);
	}

	@GET @Path("/{sessiontoken}/jwt")
	@Produces(MediaType.APPLICATION_JSON)
	@Override
	public JwtSessionRequest getJwt(@PathParam("sessiontoken") String sessiontoken) {
		return super.getJwt(sessiontoken);
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

	protected ClientQr create(SignatureClientRequest clientRequest, String verifier, String jwt) {
		SignatureProofRequest request = clientRequest.getRequest();
		if (request == null || request.getContent() == null ||
				request.getContent().size() == 0 || request.getMessage() == null)
			throw new ApiException(ApiError.MALFORMED_SIGNATURE_REQUEST);

		// Check if the requested attributes match the DescriptionStore
		if (!request.attributesMatchStore())
			throw new ApiException(ApiError.ATTRIBUTES_WRONG);

		// Check if this client is authorized to verify these attributes
		for (AttributeDisjunction disjunction : request.getContent())
			for (AttributeIdentifier identifier : disjunction)
				if (!ApiConfiguration.getInstance().canRequestSignatureWithAttribute(verifier, identifier))
					throw new ApiException(ApiError.UNAUTHORIZED, identifier.toString());

		if (clientRequest.getValidity() == 0)
			clientRequest.setValidity(DEFAULT_TOKEN_VALIDITY);

		SignatureSession session = new SignatureSession();
		return super.create(session, clientRequest, jwt);
	}

	@POST @Path("/{sessiontoken}/proofs")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public SignatureProofResult.Status proofs(ProofList proofs, @PathParam("sessiontoken") String sessiontoken)
			throws InfoException {
		SignatureSession session = sessions.getNonNullSession(sessiontoken);

		SignatureProofResult result;
		try {
			proofs.populatePublicKeyArray();
			result = session.getRequest().verify(proofs, false); // Don't allow expired attributes here
		} catch (Exception e) {
			// Everything in the verification has to be exactly right; if not, we don't accept the proofs as valid
			e.printStackTrace();
			result = new SignatureProofResult();
			result.setStatus(SignatureProofResult.Status.INVALID);
		}
		session.setResult(result);

		System.out.println("Received proofs, token: " + sessiontoken);

		return result.getStatus();
	}

	@GET @Path("/{sessiontoken}/getsignature")
	@Produces(MediaType.APPLICATION_JSON)
	public SignatureProofResult getproof(@PathParam("sessiontoken") String sessiontoken) {
		SignatureSession session = sessions.getNonNullSession(sessiontoken);
		SignatureProofResult result = session.getResult();

		if (result == null) {
			result = new SignatureProofResult();
			result.setStatus(SignatureProofResult.Status.WAITING);
		} else {
			session.close();
		}

		result.setServiceProviderData(session.getClientRequest().getData());
		return result;
	}

	@POST @Path("/checksignature")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public SignatureProofResult checkSignature(SignatureProofResult result) {
		return checkSignature(result, Calendar.getInstance().getTime(), true);
	}

	@POST @Path("/checksignature/{date}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public SignatureProofResult checkSignature(SignatureProofResult result,
	                                           @PathParam("date") String expiryDate) {
		return checkSignature(result, DatatypeConverter.parseDateTime(expiryDate).getTime(), false);
	}

	private SignatureProofResult checkSignature(SignatureProofResult result, Date expiryDate, boolean allowExpired) {
		try {
			AttributeBasedSignature signature = result.getSignature();
			if (result.getMessageType() != SignatureProofRequest.MessageType.STRING || result.getMessage() == null
					|| signature == null || signature.getNonce() == null || signature.getContext() == null) {
				System.out.println("Error in signature verification request");
				throw new ApiException(ApiError.MALFORMED_INPUT);
			}

			return signature.verify(result.getMessage(), expiryDate, allowExpired);
		} catch (ClassCastException | InfoException | KeyException e ) {
			System.out.println("Error verifying proof: ");
			e.printStackTrace();
			throw new ApiException(ApiError.EXCEPTION, e.getMessage());
		}
	}
}
