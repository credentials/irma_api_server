package org.irmacard.api.web;

import com.google.gson.JsonSyntaxException;
import io.jsonwebtoken.*;
import org.irmacard.api.common.*;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.credentials.Attributes;
import org.irmacard.api.web.IrmaSession.Status;
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
import java.security.Key;
import java.util.*;

@Path("issue")
public class IssueResource {
	private Sessions<IssueSession> sessions = Sessions.getIssuingSessions();

	/** Extracts the public key from the identity (from the JWT issuer field) from a JWT */
	private SigningKeyResolver keyresolver = new SigningKeyResolverAdapter() {
		@Override public Key resolveSigningKey(JwsHeader header, Claims claims) {
			return ApiConfiguration.getInstance().getIdentityProviderKey(claims.getIssuer());
		}
	};

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

		// Verify JWT validity
		Claims jwtContents;
		try {
			jwtContents = checkJwtToken(jwt, ApiConfiguration.getInstance().allowUnsignedJwts());
		} catch (UnsupportedJwtException|MalformedJwtException|SignatureException
				|ExpiredJwtException|IllegalArgumentException e) {
			throw new ApiException(ApiError.JWT_INVALID);
		}

		// Check if the JWT is not too old
		long now = Calendar.getInstance().getTimeInMillis();
		long issued_at = jwtContents.getIssuedAt().getTime();
		if (now - issued_at > ApiConfiguration.getInstance().getMaxJwtAge())
			throw new ApiException(ApiError.JWT_TOO_OLD,
					"Max age: " + ApiConfiguration.getInstance().getMaxJwtAge()
					+ ", was " + (now - issued_at));

		// Dirty Hack (tm): we can get a Map from Jwts, but we need an IdentityProviderRequest.
		// But the structure of the contents of the map exactly matches the fields from IdentityProviderRequest,
		// (to be more specific: either this is the case or the identity provider made a mistake),
		// so we convert the map to json, and then that json to an IdentityProviderRequest.
		Map map = jwtContents.get("iprequest", Map.class);
		String json = GsonUtil.getGson().toJson(map);
		IdentityProviderRequest request;
		try {
			request = GsonUtil.getGson().fromJson(json, IdentityProviderRequest.class);
		} catch (JsonSyntaxException e) {
			throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);
		}

		return create(request, jwtContents.getIssuer());
	}

	/**
	 * Helper function that, if allowUnsigned is true, first attempts to parse the JWT as an unsigned token and if
	 * that fails, tries parsing it as a signed JWT. In the latter case the signature will have to be valid
	 */
	private Claims checkJwtToken(String jwt, boolean allowUnsigned) {
		if (!allowUnsigned) { // Has to be signed, only try as signed JWT
			System.out.println("Trying signed JWT");
			return Jwts.parser()
					.requireSubject("issue_request")
					.setSigningKeyResolver(keyresolver)
					.parseClaimsJws(jwt)
					.getBody();
		} else { // First try to parse it as an unsigned JWT; if that fails, try it as a signed JWT
			try {
				System.out.println("Trying unsigned JWT");
				return Jwts.parser()
						.requireSubject("issue_request")
						.parseClaimsJwt(jwt)
						.getBody();
			} catch (UnsupportedJwtException e) {
				return checkJwtToken(jwt, false);
			}
		}
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

		for (CredentialRequest cred : request.getCredentials()) {
			if (!ApiConfiguration.getInstance().canIssueCredential(idp, cred.getFullName()))
				throw new ApiException(ApiError.UNAUTHORIZED, cred.getFullName());
		}

		// TODO: check if the requested attribute names match those from the DescriptionStore

		// Check if we have all necessary secret key
		for (CredentialRequest cred : request.getCredentials()) {
			try {
				IssuerDescription id = DescriptionStore.getInstance().getIssuerDescription(cred.getIssuerName());
				IdemixKeyStore.getInstance().getSecretKey(id); // Throws InfoException if we don't have it
			} catch (InfoException e) {
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
		} catch (InfoException e) {
			fail(ApiError.EXCEPTION, session);
			return null;
		} catch (CredentialsException e) {
			fail(ApiError.ISSUANCE_FAILED, session);
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
		System.out.println("Received status query, token: " + sessiontoken);

		Status status = session.getStatus();
		if (status == IssueSession.Status.DONE || status == IssueSession.Status.CANCELLED) {
			System.out.println("Removing session " + sessiontoken);
			sessions.remove(session);
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
