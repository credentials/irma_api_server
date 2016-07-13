package org.irmacard.api.web;

import org.irmacard.api.common.*;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.web.sessions.IrmaSession.Status;
import org.irmacard.api.web.sessions.IssueSession;
import org.irmacard.api.web.sessions.Sessions;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixIssuer;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.KeyException;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.ArrayList;

@Path("issue")
public class IssueResource {
	private Sessions<IssueSession> sessions = Sessions.getIssuingSessions();

	@Inject
	public IssueResource() {}

	/**
	 * Entry post for issue sessions creations. This only verifies the authenticity of the JWT; all other handling
	 * (checking if this issuer is authorized to issue, creating and saving the session, etc) is done by
	 * {@link #create(IdentityProviderRequest, String)} below.
	 */
	@POST
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.APPLICATION_JSON)
	public ClientQr newSession(String jwt) {
		if (ApiConfiguration.getInstance().isHotReloadEnabled())
			ApiConfiguration.load();

		// The entire issuing application should not be loaded if the following is false, but just to be sure
		if (!ApiConfiguration.getInstance().isIssuingEnabled())
			throw new ApiException(ApiError.ISSUING_DISABLED);

		JwtParser<IdentityProviderRequest> parser = new JwtParser<>(
				ApiConfiguration.getInstance().allowUnsignedIssueRequests(),
				"issue_request", "iprequest", "issuers", IdentityProviderRequest.class);

		// Parse and verify JWT
		IdentityProviderRequest request = parser.parseJwt(jwt).getPayload();
		return create(request, parser.getJwtIssuer());
	}

	/**
	 * Given an issuing request from a specified identity provider, check if it is authorized to issue what
	 * it wants to issue, and if we can in fact issue those credentials; if so, generate a nonce and context
	 * and store it in the sessions.
	 *
	 * @return The session token and protocol version, for the identity provider to forward to the token
	 */
	private ClientQr create(IdentityProviderRequest isRequest, String idp) {
		IssuingRequest request = isRequest.getRequest();

		if (request == null || request.getCredentials() == null || request.getCredentials().size() == 0)
			throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);

		if (isRequest.getTimeout() == 0)
			isRequest.setTimeout(ApiConfiguration.getInstance().getTokenGetTimeout());

		for (CredentialRequest cred : request.getCredentials()) {
			if (!ApiConfiguration.getInstance().canIssueCredential(idp, cred.getIdentifier()))
				throw new ApiException(ApiError.UNAUTHORIZED, cred.getFullName());
		}

		// Check if the requested credentials have the right attributes
		if (!request.credentialsMatchStore())
			throw new ApiException(ApiError.ATTRIBUTES_WRONG);

		// Check if we have all necessary secret keys
		int counter;
		for (CredentialRequest cred : request.getCredentials()) {
			try {
				IssuerIdentifier identifier = cred.getIssuerDescription().getIdentifier();
				counter = IdemixKeyStore.getInstance().getKeyCounter(identifier);
				cred.setKeyCounter(counter);
				if (!IdemixKeyStore.getInstance().containsSecretKey(identifier, counter))
					throw new ApiException(ApiError.CANNOT_ISSUE, cred.getIssuerName());
			} catch (KeyException e) {
				throw new ApiException(ApiError.CANNOT_ISSUE, cred.getIssuerName());
			}
		}

		if (ApiConfiguration.getInstance().shouldRejectUnflooredTimestamps()) {
			for (CredentialRequest cred : request.getCredentials())
				if (!cred.isValidityFloored())
					throw new ApiException(ApiError.INVALID_TIMESTAMP,
							"Epoch length: " + Attributes.EXPIRY_FACTOR);
		}

		request.setNonceAndContext();

		IssueSession session = new IssueSession(isRequest);
		String token = session.getSessionToken();
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
			fail(ApiError.UNEXPECTED_REQUEST, session);
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
			fail(ApiError.UNEXPECTED_REQUEST, session);
		}

		System.out.println("Received commitments, token: " + sessiontoken);

		IssuingRequest request = session.getRequest();
		ProofList proofs = commitments.getCombinedProofs();
		int credcount = request.getCredentials().size();
		if (proofs.size() < credcount) {
			fail(ApiError.ATTRIBUTES_MISSING, session);
		}

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
				DisclosureProofResult.Status status = disclosureRequest.verify(proofs).getStatus();

				switch (status) {
					case EXPIRED:
						fail(ApiError.ATTRIBUTES_EXPIRED, session);
					case MISSING_ATTRIBUTES:
						fail(ApiError.ATTRIBUTES_MISSING, session);
					case INVALID:
						fail(ApiError.INVALID_PROOFS, session);
				}
			}

			// Construct the CL signature for each credential to be issued.
			ArrayList<IssueSignatureMessage> sigs = new ArrayList<>(credcount);
			for (int i = 0; i < credcount; i++) {
				CredentialRequest cred = request.getCredentials().get(i);
				IdemixSecretKey sk = IdemixKeyStore.getInstance().getLatestSecretKey(
						cred.getIdentifier().getIssuerIdentifier());

				IdemixIssuer issuer = new IdemixIssuer(cred.getPublicKey(), sk, request.getContext());
				if (i == 0) {
					// Verify all commitments, but only for the first
					// credential, the others are implied
					issuer.verifyCommitments(commitments, request.getNonce());
				}
				sigs.add(issuer.issueSignatureNoCheck(
						commitments, cred.convertToBigIntegers(), i, request.getNonce()));

			}

			session.setStatusDone();
			return sigs;
		} catch (InfoException e) {
			fail(ApiError.EXCEPTION, session);
			return null;
		} catch (CredentialsException e) {
			fail(ApiError.ISSUANCE_FAILED, session);
			return null;
		} catch (KeyException e) {
			fail(ApiError.UNKNOWN_PUBLIC_KEY, session);
			return null;
		}
	}

	@DELETE
	@Path("/{sessiontoken}")
	public void delete(@PathParam("sessiontoken") String sessiontoken) {
		IssueSession session = sessions.getNonNullSession(sessiontoken);

		// Allow DELETEs only after the initial GET and before the credentials are issued
		if (session.getStatus() != IssueSession.Status.CONNECTED) {
			throw new ApiException(ApiError.UNEXPECTED_REQUEST);
		}
		System.out.println("Received delete, token: " + sessiontoken);

		session.setStatusCancelled();
	}

	@GET
	@Path("/{sessiontoken}/status")
	@Produces(MediaType.APPLICATION_JSON)
	public Status getStatus(@PathParam("sessiontoken") String sessiontoken) {
		IssueSession session = sessions.getNonNullSession(sessiontoken);

		Status status = session.getStatus();
		if (status == IssueSession.Status.DONE || status == IssueSession.Status.CANCELLED) {
			session.close();
		}

		return status;
	}

	/**
	 * Removes the session, informs the identity provider, and throws an exception to notify the token.
	 * @throws ApiException The specified exception
	 */
	private void fail(ApiError error, IssueSession session) throws ApiException {
		session.setStatusCancelled();
		throw new ApiException(error);
	}
}
