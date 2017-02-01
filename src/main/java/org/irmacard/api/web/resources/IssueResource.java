package org.irmacard.api.web.resources;

import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.CredentialRequest;
import org.irmacard.api.common.JwtSessionRequest;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.sessions.IrmaSession;
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
import java.security.KeyManagementException;
import java.util.ArrayList;

@Path("issue")
public class IssueResource extends BaseResource
		<IssuingRequest, IdentityProviderRequest, IssueSession> {

	@Inject
	public IssueResource() {
		super(Action.ISSUING, Sessions.getIssuingSessions());
	}

	@POST
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.APPLICATION_JSON)
	@Override
	public ClientQr newSession(String jwt) {
		return super.newSession(jwt);
	}

	@GET @Path("/{sessiontoken}")
	@Produces(MediaType.APPLICATION_JSON)
	@Override
	public IssuingRequest get(@PathParam("sessiontoken") String sessiontoken) {
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
	public IrmaSession.Status getStatus(@PathParam("sessiontoken") String sessiontoken) {
		return super.getStatus(sessiontoken);
	}

	@DELETE @Path("/{sessiontoken}")
	@Override
	public void delete(@PathParam("sessiontoken") String sessiontoken) {
		super.delete(sessiontoken);
	}

	/**
	 * Given an issuing request from a specified identity provider, check if it is authorized to issue what
	 * it wants to issue, and if we can in fact issue those credentials; if so, generate a nonce and context
	 * and store it in the sessions.
	 *
	 * @return The session token and protocol version, for the identity provider to forward to the token
	 */
	protected ClientQr create(IdentityProviderRequest isRequest, String idp, String jwt) {
		IssuingRequest request = isRequest.getRequest();

		if (request == null || request.getCredentials() == null || request.getCredentials().size() == 0)
			throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);

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

		IssueSession session = new IssueSession();
		return super.create(session, isRequest, jwt);
	}

	private void sendIssuestatus(String callbackUrl, String sessiontoken) {
		if (callbackUrl != null) {
			System.out.println("Posting status to: " + callbackUrl);
			try {
				sendProofResult(callbackUrl, getStatusJwt(sessiontoken));
			} catch (KeyManagementException e) {
				e.printStackTrace();
			}
		}
	}

	@POST @Path("/{sessiontoken}/commitments")
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

		String callbackUrl = session.getClientRequest().getCallbackUrl();

		if (callbackUrl != null) {
			callbackUrl += "/" + sessiontoken;
		}

		sendIssuestatus(callbackUrl, sessiontoken);

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
			sendIssuestatus(callbackUrl, sessiontoken);

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
}
