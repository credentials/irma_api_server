/*
 * SignatureTest.java
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

package org.irmacard.api.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.api.common.*;
import org.irmacard.api.common.DisclosureProofResult.Status;
import org.irmacard.api.common.SignatureProofRequest.MessageType;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test class for signature createtion and verification
 * TODO Lots of code is copied from VerificationTest, maybe merge this into something like "DisclosureTest" ?
 */
public class SignatureTest extends JerseyTest {
	public static final String schemeManager = "irma-demo";
	private static String configuration;

	public SignatureTest() {
		super(new JettyTestContainerFactory());
	}

	@BeforeClass
	public static void initializeInformation() throws InfoException {
		ApiConfiguration.testing = true;

		try {
			configuration = new String(ApiConfiguration.getResource("config.test.json"));
			ApiConfiguration.instance = GsonUtil.getGson().fromJson(configuration, ApiConfiguration.class);
			ApiConfiguration.instance.hot_reload_configuration = false;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void configureClient(ClientConfig config) {
		config.register(GsonJerseyProvider.class);
	}

	@Override
	protected Application configure() {
		enable(TestProperties.LOG_TRAFFIC);
		enable(TestProperties.DUMP_ENTITY);
		return new ApiApplication();
	}

	public String createSession(String value) throws InfoException {
		AttributeDisjunction d = new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12");
		if (value != null)
			d.getValues().put(d.get(0), value);

		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(d);
		SignatureProofRequest request = new SignatureProofRequest(null, null, attrs, "to be signed", SignatureProofRequest.MessageType.STRING);
		SignClientRequest spRequest = new SignClientRequest("testrequest", request, 60);

		Map<String, Object> claims = new HashMap<>();
		claims.put("absrequest", spRequest);
		claims.put("iss", "testsigclient");
		claims.put("sub", "signature_request");
		claims.put("iat", System.currentTimeMillis() / 1000);

		JwtBuilder builder = Jwts.builder().setPayload(GsonUtil.getGson().toJson(claims));
		String jwt = builder.compact();

		ClientQr qr = target("/signature/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(jwt, MediaType.TEXT_PLAIN), ClientQr.class);

		String sessiontoken = qr.getUrl();

		assert(sessiontoken.length() > 20);
		return sessiontoken;
	}

	public void doSession(IdemixCredential cred, List<Integer> disclosed,
	                      String session, Status expectedPostResult, Status expectedVerificationResult, boolean isSig)
			throws InfoException, KeyException, KeyManagementException {
		SignatureProofRequest request = target("/signature/" + session).request(MediaType.APPLICATION_JSON)
				.get(SignatureProofRequest.class);

		// Create the proof and post it
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getChallenge(), isSig)
				.addProofD(cred, disclosed)
				.build();
		Status status = target("/signature/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);

		assert(status == expectedPostResult);

		// Check if the unsigned proof/signature verifies if we post it to the api
		// (Note: a SP is not required to do this, just for us to test)
		SignatureProofResult result = target("/signature/" + session  +"/getunsignedproof").request(MediaType.APPLICATION_JSON)
				.get(SignatureProofResult.class);
		Status verifyResult = target("/signature/checksignature").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(result, MediaType.APPLICATION_JSON), Status.class);
		assert(verifyResult == expectedVerificationResult);

		// If status is valid, verify signature in the JSON response
		// (Note: a SP is not required to do this, just for us to test)
		if (expectedPostResult.equals(Status.VALID)) {
			AttributeBasedSignature signature = result.getSignature();
			proofs = signature.getProofs();
			proofs.populatePublicKeyArray();
			proofs.setSig(true); // This value isn't stored in the serialized signature

			// Verify signature separately without checking attributes/conditions
			assert proofs.verify(request.getContext(), request.getChallenge(), true);

			// Verify signature using the enclosed nonce, context and message data by constructing a new request
			BigInteger nonce = signature.getNonce();
			BigInteger context = signature.getContext();
			String message = (String) result.getMessage();

			assert (result.getMessageType() == MessageType.STRING);

			SignatureProofRequest resultReq = new SignatureProofRequest(nonce, context,
					new AttributeDisjunctionList(), message, MessageType.STRING);
			SignatureProofResult result2 = resultReq.verify(proofs);
			assert result2.getStatus().equals(Status.VALID);

			// Verify signature by posting result object to the checksignature method/api
			Status status2 = target("/signature/checksignature").request(MediaType.APPLICATION_JSON)
					.post(Entity.entity(result2, MediaType.APPLICATION_JSON), Status.class);
			assert status2.equals(Status.VALID);
		}
	}

	@Test
	public void validSessionTest() throws InfoException, KeyException, KeyManagementException {
		IdemixCredential cred = VerificationTest.getAgeLowerCredential();
		String session = createSession(null);
		doSession(cred, Arrays.asList(1, 2), session, Status.VALID, Status.VALID, true);
	}

	@Test
	public void verifySigAsDisclosureProofTest() throws InfoException, KeyException, KeyManagementException {
		IdemixCredential cred = VerificationTest.getAgeLowerCredential();
		String session = createSession(null);
		doSession(cred, Arrays.asList(1, 2), session, Status.INVALID, Status.INVALID, false);
	}

	@Test
	public void validSessionWithConditionTest() throws InfoException, KeyException, KeyManagementException {
		IdemixCredential cred = VerificationTest.getAgeLowerCredential();
		String session = createSession("yes");
		doSession(cred, Arrays.asList(1, 2), session, Status.VALID, Status.VALID, true);
	}

	/**
	 * If we post a proof with invalid attribute values, we should get a MISSING_ATTRIBUTES status back
	 */
	@Test
	public void validSessionWithInvalidConditionTest() throws InfoException, KeyException, KeyManagementException {
		IdemixCredential cred = VerificationTest.getAgeLowerCredential();
		String session = createSession("this is an invalid condition");
		doSession(cred, Arrays.asList(1, 2), session, Status.MISSING_ATTRIBUTES, Status.VALID, true);
	}

}
