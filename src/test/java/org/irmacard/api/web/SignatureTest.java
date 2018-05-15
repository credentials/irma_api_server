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
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.IrmaSignedMessage;
import org.irmacard.api.common.disclosure.DisclosureProofResult.Status;
import org.irmacard.api.common.signatures.SignatureClientRequest;
import org.irmacard.api.common.signatures.SignatureProofRequest;
import org.irmacard.api.common.signatures.SignatureProofResult;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.*;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.KeyException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.util.*;

/**
 * Test class for signature createtion and verification
 */
public class SignatureTest extends JerseyTest {
	private static final String schemeManager = "irma-demo";

	public SignatureTest() {
		super(new JettyTestContainerFactory());
	}

	@BeforeClass
	public static void initializeInformation() {
		ApiConfiguration.testing = true;

		try {
			String configuration = new String(ApiConfiguration.getResource("config.test.json"));
			ApiConfiguration.instance = GsonUtil.getGson().fromJson(configuration, ApiConfiguration.class);
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

	private String createSession(String value) throws InfoException {
		AttributeDisjunction d = new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12");
		if (value != null)
			d.getValues().put(d.get(0), value);

		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(d);
		SignatureProofRequest request = new SignatureProofRequest(BigInteger.ONE, BigInteger.ONE, attrs, "to be signed");
		SignatureClientRequest spRequest = new SignatureClientRequest("testrequest", request, 60);

		Map<String, Object> claims = new HashMap<>();
		claims.put("absrequest", spRequest);
		claims.put("iss", "testsigclient");
		claims.put("sub", "signature_request");
		claims.put("iat", System.currentTimeMillis() / 1000);

		String jwt = Jwts.builder().setPayload(GsonUtil.getGson().toJson(claims)).compact();
		ClientQr qr = target("/signature/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(jwt, MediaType.TEXT_PLAIN), ClientQr.class);

		String sessiontoken = qr.getUrl();

		assert(sessiontoken.length() > 20);
		return sessiontoken;
	}

	private SignatureProofResult parseJwt(String jwt) throws KeyManagementException {
		Claims claims = Jwts.parser()
				.requireSubject("abs_result")
				.setSigningKey(ApiConfiguration.getInstance().getJwtPublicKey())
				.parseClaimsJws(jwt)
				.getBody();

		String json = GsonUtil.getGson().toJson(claims);
		return GsonUtil.getGson().fromJson(json, SignatureProofResult.class);
	}

	private void doSession(IdemixCredential cred, List<Integer> disclosed,
	                      String session, Status expectedPostResult, Status expectedVerificationResult, boolean isSig)
			throws InfoException, KeyException, KeyManagementException {
		SignatureProofRequest request = target("/signature/" + session).request(MediaType.APPLICATION_JSON)
				.get(SignatureProofRequest.class);

		// Create the proof and post it
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce(), isSig)
				.addProofD(cred, disclosed)
				.build();
		IrmaSignedMessage irmaSignedMessage = new IrmaSignedMessage(proofs, request.getSignatureNonce(), request.getContext(), request.getMessage());
		Status status = target("/signature/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(irmaSignedMessage, MediaType.APPLICATION_JSON), Status.class);

		assert(status == expectedPostResult);


		// Verify the token itself, and that the credential was valid
		String jwt = target("/signature/" + session +"/getsignature").request(MediaType.TEXT_PLAIN)
				.get(String.class);
		SignatureProofResult result = parseJwt(jwt);

		// Verify 'stateless' api
		jwt = target("/signature/checksignature").request(MediaType.TEXT_PLAIN)
				.post(Entity.entity(irmaSignedMessage, MediaType.APPLICATION_JSON), String.class);
		result = parseJwt(jwt);
		assert(result.getStatus() == expectedVerificationResult);

		// If status is valid, verify signature in the JSON response
		// (Note: a SP is not required to do this, just for us to test)
		if (expectedPostResult.equals(Status.VALID)) {
			IrmaSignedMessage signature = result.getSignature();
			proofs = signature.getProofs();
			proofs.populatePublicKeyArray();
			proofs.setSig(true); // This value isn't stored in the serialized signature

			// Verify signature separately without checking attributes/conditions
			assert proofs.verify(request.getContext(), request.getNonce(), true);

			// Verify signature using the enclosed nonce, context and message data by constructing a new request
			BigInteger nonce = signature.getNonce();
			BigInteger context = signature.getContext();
			String message = signature.getMessage();

			SignatureProofRequest resultReq = new SignatureProofRequest(nonce, context,
					new AttributeDisjunctionList(), message);
			result = resultReq.verify(proofs, false);
			assert result.getStatus().equals(Status.VALID);
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

	private IdemixCredential issue(Date signDate) throws KeyException, InfoException, CredentialsException {
		// Meta info
		IssuerIdentifier issuerId = new IssuerIdentifier(schemeManager + ".MijnOverheid");
		CredentialIdentifier credId = new CredentialIdentifier(issuerId, "ageLower");

		// Crypto parameters
		IdemixPublicKey pk = IdemixKeyStore.getInstance().getLatestPublicKey(issuerId);
		IdemixSecretKey sk = IdemixKeyStore.getInstance().getLatestSecretKey(issuerId);
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		// Compute metadata attribute and generate random attributes
		Attributes attrs = new Attributes();
		attrs.setCredentialIdentifier(credId);
		List<BigInteger> attrInts = new ArrayList<>(Arrays.asList(secret, new BigInteger(attrs.get(Attributes.META_DATA_FIELD))));
		for (int i=0; i<4; ++i)
			attrInts.add(new BigInteger(params.get_l_m(), rnd));
		attrs = new Attributes(attrInts);
		attrs.setSigningDate(signDate);
		attrInts = attrs.toBigIntegers();

		// Do the issuing
		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		CredentialBuilder cb = new CredentialBuilder(pk, attrInts, context);
		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attrInts, n_1);

		return cb.constructCredential(msg);
	}

	@Test
	public void expiredAttributeSession()
	throws InfoException, KeyException, KeyManagementException, CredentialsException {
		oldAttributesTest(null);
	}

	@Test
	public void oldSignatureSession()
	throws InfoException, KeyException, KeyManagementException, CredentialsException {
		Calendar exp = Calendar.getInstance();
		exp.add(Calendar.MONTH, -21);
		oldAttributesTest(exp.getTime());
	}

	private void oldAttributesTest(Date verificationDate)
	throws InfoException, KeyException, KeyManagementException, CredentialsException {
		Calendar exp = Calendar.getInstance();
		exp.add(Calendar.YEAR, -2);

		final BigInteger nonce = BigInteger.TEN;
		final BigInteger context = BigInteger.ONE;
		final String message = "foo";

		SignatureProofRequest request = new SignatureProofRequest(
				nonce, context, null, message);
		ProofList proofs = new ProofListBuilder(context, request.getNonce(), true)
				.addProofD(issue(exp.getTime()), Arrays.asList(1, 2))
				.build();

		IrmaSignedMessage signature = new IrmaSignedMessage(proofs, nonce, context, message);

		if (verificationDate == null) {
			String jwt = target("/signature/checksignature")
					.request(MediaType.TEXT_PLAIN)
					.post(Entity.entity(signature, MediaType.APPLICATION_JSON), String.class);
			SignatureProofResult verifyResult = parseJwt(jwt);
			assert (verifyResult.getStatus() == Status.EXPIRED);
		} else {
			String jwt = target("/signature/checksignature/" + verificationDate.getTime()/1000)
					.request(MediaType.TEXT_PLAIN)
					.post(Entity.entity(signature, MediaType.APPLICATION_JSON), String.class);
			SignatureProofResult verifyResult = parseJwt(jwt);
			assert (verifyResult.getStatus() == Status.VALID);
		}
	}

	@Test
	private void go() throws IOException {
		String command = "ls";
		Process child = Runtime.getRuntime().exec(command);
		InputStream in = child.getInputStream();
	}
}
