package org.irmacard.api.web;

import org.irmacard.api.common.CredentialRequest;
import org.irmacard.api.common.IdentityProviderRequest;
import org.irmacard.api.common.IssuingRequest;
import org.irmacard.api.web.exceptions.InputInvalidException;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixIssuer;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;
import org.irmacard.api.common.DisclosureProofRequest;
import org.irmacard.api.common.DisclosureQr;
import org.irmacard.api.common.util.GsonUtil;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.math.BigInteger;
import java.util.*;

@Path("issue")
public class IssueResource {
	private Sessions<IssueSession> sessions = Sessions.getIssuingSessions();

	@Inject
	public IssueResource() {}

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public DisclosureQr create(IdentityProviderRequest isRequest) throws InfoException {
		IssuingRequest request = isRequest.getRequest();

		// Check if we have all necessary secret keys
		for (CredentialRequest cred : request.getCredentials()) {
			IssuerDescription id = DescriptionStore.getInstance().getIssuerDescription(cred.getIssuerName());
			IdemixKeyStore.getInstance().getSecretKey(id); // Throws InfoException if we don't have it, TODO handle better
		}

		request.setNonce(DisclosureProofRequest.generateNonce());
		if (request.getContext() == null || request.getContext().equals(BigInteger.ZERO))
			request.setContext(Crypto.sha256Hash("TODO".getBytes())); // TODO

		String token = Sessions.generateSessionToken();
		IssueSession session = new IssueSession(token, isRequest);
		sessions.addSession(session);

		System.out.println("Received issue session, token: " + token);
		System.out.println(GsonUtil.getGson().toJson(isRequest));

		return new DisclosureQr("2.0", token);
	}

	@GET
	@Path("/{sessiontoken}")
	@Produces(MediaType.APPLICATION_JSON)
	public IssuingRequest get(@PathParam("sessiontoken") String sessiontoken) {
		System.out.println("Received get, token: " + sessiontoken);

		IssueSession session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.INITIALIZED) {
			throw new InputInvalidException("Unexpected command");
		}

		session.setStatusConnected();
		return session.getRequest();
	}

	@POST
	@Path("/{sessiontoken}/commitments")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ArrayList<IssueSignatureMessage> getSignatureMessages(IssueCommitmentMessage commitments,
			@PathParam("sessiontoken") String sessiontoken) throws InfoException, CredentialsException {
		IssueSession session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.CONNECTED) {
			throw new InputInvalidException("Unexpected command");
		}

		IssuingRequest request = session.getRequest();
		ProofList proofs = commitments.getCombinedProofs();
		int credcount = request.getCredentials().size();
		if (proofs.size() < credcount)
			throw new InputInvalidException("Proof count does not match credential count");

		// Lookup the public keys of any ProofD's in the proof list
		proofs.populatePublicKeyArray();

		// Lookup the public keys of all ProofU's in the proof list
		ArrayList<IssueSignatureMessage> sigs = new ArrayList<>(credcount);
		for (int i = 0; i < credcount; i++) {
			CredentialRequest cred = request.getCredentials().get(i);
			proofs.setPublicKey(i, cred.getPublicKey());
		}

		// Construct the CL signature for each credential to be issued. This also checks the validity of the commitments
		for (int i = 0; i < credcount; i++) {
			CredentialRequest cred = request.getCredentials().get(i);
			IdemixSecretKey sk = IdemixKeyStore.getInstance().getSecretKey(cred.getIssuerDescription());

			IdemixIssuer issuer = new IdemixIssuer(cred.getPublicKey(), sk, request.getContext());
			sigs.add(issuer.issueSignature(
					commitments, cred.convertToBigIntegers(), i, request.getNonce()));
		}

		return sigs;
	}
}
