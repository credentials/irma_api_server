package org.irmacard.api.web;

import org.irmacard.api.common.*;
import org.irmacard.api.web.exceptions.InputInvalidException;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixIssuer;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;
import org.irmacard.api.common.util.GsonUtil;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

@Path("issue")
public class IssueResource {
	private Sessions<IssueSession> sessions = Sessions.getIssuingSessions();

	@Inject
	public IssueResource() {}

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ClientQr create(IdentityProviderRequest isRequest) {
		IssuingRequest request = isRequest.getRequest();

		if (request == null || request.getCredentials() == null || request.getCredentials().size() == 0)
			throw new InputInvalidException("Incomplete request");

		try {
			// Check if we have all necessary secret keys
			for (CredentialRequest cred : request.getCredentials()) {
				IssuerDescription id = DescriptionStore.getInstance().getIssuerDescription(cred.getIssuerName());
				IdemixKeyStore.getInstance().getSecretKey(id); // Throws InfoException if we don't have it
			}
		} catch (InfoException e) {
			throw new WebApplicationException("Missing Idemix secret key", Response.Status.UNAUTHORIZED);
		}

		request.setNonceAndContext();

		String token = Sessions.generateSessionToken();
		IssueSession session = new IssueSession(token, isRequest);
		sessions.addSession(session);

		System.out.println("Received issue session, token: " + token);
		System.out.println(GsonUtil.getGson().toJson(isRequest));

		return new ClientQr("2.0", token);
	}

	@GET
	@Path("/{sessiontoken}")
	@Produces(MediaType.APPLICATION_JSON)
	public IssuingRequest get(@PathParam("sessiontoken") String sessiontoken) {
		IssueSession session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.INITIALIZED) {
			fail(new WebApplicationException(Response.Status.UNAUTHORIZED), session);
		}

		System.out.println("Received get, token: " + sessiontoken);

		session.setStatusConnected();
		return session.getRequest();
	}

	@POST
	@Path("/{sessiontoken}/commitments")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ArrayList<IssueSignatureMessage> getSignatureMessages(IssueCommitmentMessage commitments,
			@PathParam("sessiontoken") String sessiontoken) throws WebApplicationException {
		IssueSession session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.CONNECTED) {
			fail(new WebApplicationException(Response.Status.UNAUTHORIZED), session);
		}

		System.out.println("Received commitments, token: " + sessiontoken);

		IssuingRequest request = session.getRequest();
		ProofList proofs = commitments.getCombinedProofs();
		int credcount = request.getCredentials().size();
		if (proofs.size() < credcount)
			fail(new InputInvalidException("Proof count does not match credential count"), session);

		// Lookup the public keys of any ProofD's in the proof list
		proofs.populatePublicKeyArray();

		try {
			// Lookup the public keys of all ProofU's in the proof list. We have to do this before we can compute the CL
			// sigatures below, because that also verifies the proofs, which needs these keys.
			proofs.populatePublicKeyArray();
			int disclosureCount = proofs.getProofDCount();
			for (int i = 0; i < credcount; i++) {
				CredentialRequest cred = request.getCredentials().get(i);
				proofs.setPublicKey(disclosureCount + i, cred.getPublicKey());
			}

			// If any disclosures are required before we give the credentials, verify that they are present and correct
			if (request.getRequiredAttributes().size() > 0) {
				DisclosureProofRequest disclosureRequest = new DisclosureProofRequest(
						request.getNonce(), request.getContext(), request.getRequiredAttributes());
				if (disclosureRequest.verify(proofs).getStatus() != DisclosureProofResult.Status.VALID) {
					fail(new InputInvalidException("Incorrect disclosure proof"), session);
				}
			}

			// Construct the CL signature for each credential to be issued.
			// FIXME This also checks the validity of _all_ proofs, for each iteration - so more than once
			ArrayList<IssueSignatureMessage> sigs = new ArrayList<>(credcount);
			for (int i = 0; i < credcount; i++) {
				CredentialRequest cred = request.getCredentials().get(i);
				IdemixSecretKey sk = IdemixKeyStore.getInstance().getSecretKey(cred.getIssuerDescription());

				IdemixIssuer issuer = new IdemixIssuer(cred.getPublicKey(), sk, request.getContext());
				sigs.add(issuer.issueSignature(
						commitments, cred.convertToBigIntegers(), i, request.getNonce()));
			}

			session.setStatusDone();
			return sigs;
		} catch (InfoException|CredentialsException e) {
			fail(new WebApplicationException(e), session);
			return null;
		}
	}

	@DELETE
	@Path("/{sessiontoken}")
	public void delete(@PathParam("sessiontoken") String sessiontoken) {
		IssueSession session = sessions.getNonNullSession(sessiontoken);
		System.out.println("Received delete, token: " + sessiontoken);

		session.setStatusCancelled();
	}

	@GET
	@Path("/{sessiontoken}/getstatus")
	@Produces(MediaType.TEXT_PLAIN)
	public String getStatus(@PathParam("sessiontoken") String sessiontoken) {
		IssueSession session = sessions.getNonNullSession(sessiontoken);
		System.out.println("Received status query, token: " + sessiontoken);

		IssueSession.Status status = session.getStatus();
		if (status == IssueSession.Status.DONE || status == IssueSession.Status.CANCELLED)
			sessions.remove(session);

		return status.toString();
	}

	/**
	 * Removes the session, informs the identity provider, and throws the exception to notify the token.
	 * @throws WebApplicationException The specified exception
	 */
	private void fail(WebApplicationException e, IssueSession session) throws WebApplicationException {
		session.setStatusCancelled();
		throw e;
	}
}
