package org.irmacard.api.web;

import foundation.privacybydesign.common.BaseConfiguration;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.CredentialRequest;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.CredentialBuilder;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class IssueTest extends JerseyTest {
	public IssueTest() {
		super(new JettyTestContainerFactory());
	}

	@BeforeClass
	public static void initializeInformation() throws InfoException {
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

	@Test // Valid issuance without disclosure
	public void validIssueTest()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		doIssueSession(getAgeLowerIPrequest(), null);
	}

	// Issuance with missing required attribute (without disclosure)
	@Test(expected=BadRequestException.class)
	public void requiredAttributeTest()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		IdentityProviderRequest req = getAgeLowerIPrequest();
		req.getRequest().getCredentials().get(0).getAttributes().remove("over18");
		doIssueSession(req, null);
	}

	@Test // Valid issuance with disclosure of 1 attribute
	public void validBoundIssueTest()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		IdemixCredential ageLower = doIssueSession(getAgeLowerIPrequest(), null).get(0);
		doIssueSession(getBoundIPrequest("\"irma-demo.MijnOverheid.ageLower.over12\": \"yes\""), ageLower);
	}

	@Test // Valid issuance with proof of ownership of a credential (no attribute disclosure)
	public void validBoundIssueTest2()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		IdemixCredential ageLower = doIssueSession(getAgeLowerIPrequest(), null).get(0);
		doIssueSession(getBoundIPrequest("\"irma-demo.MijnOverheid.ageLower\": \"present\""), ageLower);
	}

	// Issuance where an attribute with the wrong value is disclosed
	@Test(expected=BadRequestException.class)
	public void boundIssueWrongValueTest()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		IdemixCredential ageLower = doIssueSession(getAgeLowerIPrequest(), null).get(0);
		doIssueSession(getBoundIPrequest("\"irma-demo.MijnOverheid.ageLower.over12\": \"no\""), ageLower);
	}

	// Issuance where a disclosed attribute is expected but not provided
	@Test(expected=BadRequestException.class)
	public void boundIssueMissingValueTest()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		doIssueSession(getBoundIPrequest("\"irma-demo.MijnOverheid.ageLower.over12\": \"yes\""), null);
	}

	// Issuance where a credential ownership proof is expected but not provided
	@Test(expected=BadRequestException.class)
	public void boundIssueMissingValueTest2()
	throws CredentialsException, InfoException, KeyManagementException, KeyException {
		doIssueSession(getBoundIPrequest("\"irma-demo.MijnOverheid.ageLower\": \"present\""), null);
	}

	/**
	 * Perform an issuing session, disclosing all attributes of the specified credential if present.
	 */
	public ArrayList<IdemixCredential> doIssueSession(IdentityProviderRequest ipRequest, IdemixCredential cred)
	throws KeyManagementException, InfoException, CredentialsException, KeyException {
		String sessiontoken = createSession(ipRequest);

		IssuingRequest request = target("/issue/" + sessiontoken)
				.request(MediaType.APPLICATION_JSON).get(IssuingRequest.class);

		ArrayList<CredentialBuilder> credentialBuilders = new ArrayList<>(request.getCredentials().size());
		IssueCommitmentMessage msg = getIssueCommitments(request, credentialBuilders, cred);

		ArrayList<IssueSignatureMessage> signatures = target("/issue/" + sessiontoken + "/commitments")
				.request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(msg, MediaType.APPLICATION_JSON),
						new GenericType<ArrayList<IssueSignatureMessage>>(){});

		ArrayList<IdemixCredential> creds = new ArrayList<>();
		for (int i = 0; i < signatures.size(); ++i)
			creds.add(credentialBuilders.get(i).constructCredential(signatures.get(i)));
		return creds;
	}

	/** Partly copied from CredentialManager.java from the cardemu app */
	public IssueCommitmentMessage getIssueCommitments(IssuingRequest request,
	                                                  ArrayList<CredentialBuilder> credentialBuilders,
	                                                  IdemixCredential credential)
	throws InfoException, CredentialsException, KeyException {
		BigInteger nonce2 = CredentialBuilder.createReceiverNonce(request.getCredentials().get(0).getPublicKey());

		// Construct the commitment proofs
		ProofListBuilder proofsBuilder = new ProofListBuilder(request.getContext(), request.getNonce());
		proofsBuilder.setSecretKey(BigInteger.TEN);

		for (CredentialRequest cred : request.getCredentials()) {
			CredentialBuilder cb = new CredentialBuilder(
					cred.getPublicKey(), cred.convertToBigIntegers(), request.getContext(), nonce2);
			proofsBuilder.addCredentialBuilder(cb);
			credentialBuilders.add(cb);
		}

		// For simplicity, we just disclose all attributes of this credential, without checking
		// if they match what is asked for in the IssuingRequest.
		if (credential != null)
			proofsBuilder.addProofD(credential, Arrays.asList(1,2,3,4,5));

		return new IssueCommitmentMessage(proofsBuilder.build(), nonce2);
	}


	public String createSession(IdentityProviderRequest ipRequest) throws KeyManagementException {
		String jwt = getJwt(ipRequest,
				System.currentTimeMillis()/1000,
				ApiConfiguration.getInstance().getPrivateKey("test-sk.der"));

		ClientQr qr = target("/issue/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(jwt, MediaType.TEXT_PLAIN), ClientQr.class);

		return qr.getUrl();
	}

	public String getJwt(IdentityProviderRequest ipRequest, long issuedAt, PrivateKey key) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("iprequest", ipRequest);
		claims.put("iss", "testip");
		claims.put("sub", "issue_request");
		claims.put("iat", issuedAt);

		return Jwts.builder()
				.setPayload(GsonUtil.getGson().toJson(claims))
				.signWith(ApiConfiguration.getInstance().getJwtAlgorithm(), key)
				.compact();
	}

	public IdentityProviderRequest getAgeLowerIPrequest() {
		String json = "{\"data\":\"foobar\",\"timeout\":60,\"request\":{\"credentials\":[{\"credential\":\"irma-demo.MijnOverheid.ageLower\",\"validity\":1893024000,\"attributes\":{\"over12\":\"yes\",\"over16\":\"yes\",\"over18\":\"yes\",\"over21\":\"no\"}}]}}";
		return GsonUtil.getGson().fromJson(json, IdentityProviderRequest.class);
	}

	public IdentityProviderRequest getBoundIPrequest(String toDisclose) {
		String json = "{\"data\": \"foobar\",\"timeout\": 60,\"request\": {\"credentials\": [{\"credential\": \"irma-demo.MijnOverheid.ageLower\",\"validity\": 1893024000,\"attributes\": {\"over12\": \"yes\",\"over16\": \"yes\",\"over18\": \"yes\",\"over21\": \"no\"}}],\"disclose\": [{\"label\": \"Age (lower)\",\"attributes\": {"
		+ toDisclose + "}}]}}";
		return GsonUtil.getGson().fromJson(json, IdentityProviderRequest.class);
	}
}
