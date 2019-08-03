package org.irmacard.api.web.resources;

import io.jsonwebtoken.*;
import org.irmacard.api.common.*;
import org.irmacard.api.common.JwtParser;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.Historian;
import org.irmacard.api.web.sessions.IrmaSession;
import org.irmacard.api.web.sessions.IssueSession;
import org.irmacard.api.web.sessions.Sessions;
import org.irmacard.api.web.sessions.VerificationSession;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixIssuer;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofP;
import org.irmacard.credentials.info.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.security.Key;
import java.security.KeyManagementException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import javax.ws.rs.core.Context;
import javax.servlet.http.HttpServletRequest;

@Path("issue")
public class IssueResource extends BaseResource
		<IssuingRequest, IdentityProviderRequest, IssueSession> {

	private static Logger logger = LoggerFactory.getLogger(IssueResource.class);

	@Context
	private HttpServletRequest servletRequest;

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
	public IssuingRequest get(@PathParam("sessiontoken") String sessiontoken,
	                          @HeaderParam("X-IRMA-MinProtocolVersion") ProtocolVersion minVersion,
	                          @HeaderParam("X-IRMA-MaxProtocolVersion") ProtocolVersion maxVersion) {
		return super.get(sessiontoken, minVersion, maxVersion);
	}

	@GET @Path("/{sessiontoken}/jwt")
	@Produces(MediaType.APPLICATION_JSON)
	@Override
	public JwtSessionRequest getJwt(@PathParam("sessiontoken") String sessiontoken, @HeaderParam("X-IRMA-ProtocolVersion") ProtocolVersion version) {
		return super.getJwt(sessiontoken, version);
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
		ApiConfiguration conf = ApiConfiguration.getInstance();
		IssuingRequest request = isRequest.getRequest();
		boolean isDistributed = false;
		int counter;
		String keyshareManager = null;

		if (request == null || request.getCredentials() == null || request.getCredentials().size() == 0)
			throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);

		for (CredentialRequest cred : request.getCredentials()) {
			if (!conf.canIssueCredential(idp, cred.getIdentifier()))
				throw new ApiException(ApiError.UNAUTHORIZED, cred.getFullName());

			String schemeManager = cred.getIdentifier().getSchemeManagerName();
			if (DescriptionStore.getInstance().getSchemeManager(schemeManager).hasKeyshareServer()) {
				isDistributed = true;
				if (keyshareManager == null) {
					keyshareManager = schemeManager;
				} else if (!keyshareManager.equals(schemeManager)) { // We don't yet support issuance sessions with multiple keyshare servers
					throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);
				}
			}

			// Check if we have all necessary secret keys
			try {
				IssuerIdentifier identifier = cred.getIssuerDescription().getIdentifier();
				counter = IdemixKeyStore.getInstance().getKeyCounter(identifier);
				cred.setKeyCounter(counter);
				if (!IdemixKeyStore.getInstance().containsSecretKey(identifier, counter))
					throw new ApiException(ApiError.CANNOT_ISSUE, cred.getIssuerName());
			} catch (KeyException e) {
				throw new ApiException(ApiError.CANNOT_ISSUE, cred.getIssuerName());
			}

			if (conf.shouldRejectUnflooredTimestamps() && !cred.isValidityFloored())
				throw new ApiException(ApiError.INVALID_TIMESTAMP,  "Epoch length: " + Attributes.EXPIRY_FACTOR);
		}

		// Check if the requested credentials have the right attributes
		if (!request.credentialsMatchStore())
			throw new ApiException(ApiError.ATTRIBUTES_WRONG);

		logger.info("Received issuance session");
		for (CredentialRequest cred : request.getCredentials())
			logger.info("type: {}", cred.getIdentifier().toString());

		IssueSession session = new IssueSession(isDistributed);
		return super.create(session, isRequest, jwt);
	}

	private HashMap<String, ProofP> proofps = new HashMap<>();
	private static final ProtocolVersion proofpProtocolVersionBoundary = new ProtocolVersion("2.4");
	private ProofP extractProofP(IssueSession session, IssueCommitmentMessage commitments, final String schemeManager) {
		if (proofps.containsKey(schemeManager))
			return proofps.get(schemeManager);

		// If the scheme mamanger uses a keyshare server, the JWT has to be present and valid
		// If it is not, jwtParser.parseJwt() throws an exception.
		String jwt;
		if (session.getVersion().below(proofpProtocolVersionBoundary))
			jwt = commitments.getProofPJwt();
		else
			jwt = commitments.getProofPJwt(schemeManager);
		if (jwt == null)
			fail(ApiError.KEYSHARE_PROOF_MISSING, session);
		JwtParser<ProofP> jwtParser = new JwtParser<>(ProofP.class, false, 60*1000, "ProofP", "ProofP");
		jwtParser.setKeyResolver(new SigningKeyResolverAdapter() {
			@Override public Key resolveSigningKey(JwsHeader header, Claims claims) {
				String keyId = (String) header.get("kid");
				if (keyId == null || keyId.length() == 0)
					keyId = "0";
				return ApiConfiguration.getInstance().getKssPublicKey(schemeManager, keyId);
			}
		});
		ProofP proof = jwtParser.parseJwt(jwt).getPayload();

		proofps.put(schemeManager, proof);
		return proof;
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

		logger.info("Received commitments, token: " + sessiontoken);

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
			for (int i = 0; i < proofs.size(); i++) {
				IdemixPublicKey pk;
				if (i < disclosureCount) {
					// This is a disclosure proof, so we get the public key from the metadata attribute
					pk = proofs.get(i).extractPublicKey();
				} else {
					pk = request.getCredentials().get(i - disclosureCount).getPublicKey();
					proofs.setPublicKey(i, pk);
				}

				SchemeManager scheme = pk.getIssuerIdentifier().getSchemeManager();
				if (scheme.hasKeyshareServer()) {
					ProofP proofP = extractProofP(session, commitments, scheme.getName());
					proofs.get(i).mergeProofP(proofP, pk);
				}
			}

			// If any disclosures are required before we give the credentials, verify that they are present and correct
			if (request.getRequiredAttributes().size() > 0) {
				DisclosureProofRequest disclosureRequest = new DisclosureProofRequest(
						request.getNonce(), request.getContext(), request.getRequiredAttributes());
				DisclosureProofResult res = disclosureRequest.verify(proofs);
				session.setDisclosed(res);

				switch (res.getStatus()) {
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
				byte metadataVersion = getMetadataVersion(session.getVersion());
				sigs.add(issuer.issueSignatureNoCheck(
						commitments, cred.convertToBigIntegers(metadataVersion), i, request.getNonce()));

				ApiConfiguration conf = ApiConfiguration.getInstance();
				Historian.getInstance().recordIssue(cred.getIdentifier().toString(), conf.getClientIp(servletRequest));
			}

			session.setStatusDone();
			return sigs;
		} catch (InfoException e) {
			e.printStackTrace();
			fail(ApiError.EXCEPTION, session);
			return null;
		} catch (CredentialsException e) {
			e.printStackTrace();
			fail(ApiError.ISSUANCE_FAILED, session);
			return null;
		} catch (KeyException e) {
			e.printStackTrace();
			fail(ApiError.UNKNOWN_PUBLIC_KEY, session);
			return null;
		} catch (JwtException|IllegalArgumentException e) {
			e.printStackTrace();
			fail(ApiError.JWT_INVALID, session);
			return null;
		} catch (ApiException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			fail(ApiError.EXCEPTION, session);
			return null;
		}
	}

	public DisclosureProofResult getproof(String sessiontoken) {
		IssueSession session = sessions.getNonNullSession(sessiontoken);
		DisclosureProofResult result = session.getDisclosed();
		if (result == null)
			throw new ApiException(ApiError.UNEXPECTED_REQUEST, "No attributes were disclosed in this session");
		result.setServiceProviderData(session.getClientRequest().getData());
		return result;
	}

	@GET @Path("/{sessiontoken}/getproof")
	@Produces(MediaType.TEXT_PLAIN)
	public String gettoken(@PathParam("sessiontoken") String sessiontoken) throws KeyManagementException {
		return signResultJwt(getproof(sessiontoken), 120, "issue_result");
	}

}
