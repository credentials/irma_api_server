package org.irmacard.api.web.resources;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import org.irmacard.api.common.*;
import org.irmacard.api.common.disclosure.ServiceProviderRequest;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.common.signatures.SignatureClientRequest;
import org.irmacard.api.common.signatures.SignatureProofRequest;
import org.irmacard.api.web.ApiApplication;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.sessions.*;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.Key;
import java.util.HashMap;

public abstract class BaseResource
		<RequestClass extends SessionRequest,
		ClientClass extends ClientRequest<RequestClass>,
		SessionClass extends IrmaSession<ClientClass, RequestClass>> {

	private static Logger logger = LoggerFactory.getLogger(BaseResource.class);
	private static final ProtocolVersion optionalAttributesProtocolBoundary = new ProtocolVersion("2.3");

	/* Template boilerplate to keep the type system happy. Getting rather crazy here,
	 * but the code deduplication is worth it, I deem. The following enum works around
	 * Java's generic type erasure. */

	/**
	 * For each of the main three actions of verification, signing and issuing,
	 * this enum keeps track of the .class objects of the three template arguments
	 * given to this {@link BaseResource}.
	 */
	public enum Action {
		DISCLOSING(SignatureProofRequest.class, ServiceProviderRequest.class, VerificationSession.class),
		SIGNING(SignatureProofRequest.class, SignatureClientRequest.class, SignatureSession.class),
		ISSUING(IssuingRequest.class, IdentityProviderRequest.class, SignatureSession.class);

		final Class<? extends SessionRequest> RequestClass;
		final Class<? extends ClientRequest> ClientClass;
		final Class<? extends IrmaSession> SessionClass;

		Action(Class<? extends SessionRequest> requestClass,
		       Class<? extends ClientRequest> clientClass,
		       Class<? extends IrmaSession> sessionClass) {
			SessionClass = sessionClass;
			ClientClass = clientClass;
			RequestClass = requestClass;
		}
	}

	protected Sessions<SessionClass> sessions;
	protected Action action;

	public BaseResource(Action action, Sessions<SessionClass> sessions) {
		this.action = action;
		this.sessions = sessions;
	}

	// Base methods for subclasses to use

	public ClientQr newSession(String jwt) {
		@SuppressWarnings("unchecked")
		JwtParser<ClientClass> parser = (JwtParser<ClientClass>) new JwtParser<>(action.ClientClass,
				ApiConfiguration.getInstance().allowUnsignedRequests(action),
				ApiConfiguration.getInstance().getMaxJwtAge());

		parser.setKeyResolver(new SigningKeyResolverAdapter() {
			@Override public Key resolveSigningKey(JwsHeader header, Claims claims) {
				String keyId = (String) header.get("kid");
				if (keyId == null)
					keyId = claims.getIssuer();
				else {
					if (!ApiConfiguration.getInstance().getClientName(keyId).equals(claims.getIssuer()))
						throw new ApiException(ApiError.JWT_INVALID);
				}
				return ApiConfiguration.getInstance().getClientPublicKey(action, keyId);
			}
		});

		parser.parseJwt(jwt);
		String keyId = parser.getKeyIdentifier();
		ClientClass request = parser.getPayload();
		return create(request, keyId, jwt);
	}

	protected abstract ClientQr create(ClientClass clientRequest, String issuer, String jwt);

	protected ClientQr create(SessionClass session, ClientClass clientRequest, String jwt) {
		if (clientRequest.getTimeout() == 0)
			clientRequest.setTimeout(ApiConfiguration.getInstance().getTokenGetTimeout());
		session.setClientRequest(clientRequest);

		RequestClass request = clientRequest.getRequest();
		request.setNonceAndContext();

		session.setJwt(jwt);
		String token = session.getSessionToken();
		sessions.addSession(session);

		String minVersion = ApiApplication.minVersion.toString();
		String maxVersion = ApiApplication.maxVersion.toString();
		return new ClientQr(minVersion, maxVersion, token, action.name().toLowerCase());
	}

	private ProtocolVersion chooseProtocolVersion(ProtocolVersion min, ProtocolVersion max) {
		if (min.above(ApiApplication.maxVersion) || max.below(ApiApplication.minVersion))
			throw new RuntimeException("Protocol version negotiation failed: no acceptable protocol version in range");

		if (max.above(ApiApplication.maxVersion))
			return ApiApplication.maxVersion;
		else
			return max;
	}

	public RequestClass get(String sessiontoken, ProtocolVersion minVersion, ProtocolVersion maxVersion) {
		logger.info("Received get, token: " + sessiontoken);

		SessionClass session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.INITIALIZED) {
			fail(ApiError.UNEXPECTED_REQUEST, session);
		}

		session.setVersion(chooseProtocolVersion(minVersion, maxVersion));
		session.setStatusConnected();
		return session.getRequest();
	}

	public JwtSessionRequest getJwt(String sessiontoken, ProtocolVersion version) {
		logger.info("Received jwt get, token: " + sessiontoken);
		SessionClass session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.INITIALIZED) {
			fail(ApiError.UNEXPECTED_REQUEST, session);
		}

		if (version != null)
			session.setVersion(version); // >= 2.3
		else
			session.setVersion(new ProtocolVersion("2.2")); // < 2.3

		session.setStatusConnected();
		RequestClass request = session.getRequest();
		BigInteger nonce = request.getNonce();
		if (action == Action.SIGNING)
			nonce = ((SignatureProofRequest) request).getSignatureNonce();

		// Only relevant for issuing
		HashMap<IssuerIdentifier, Integer> pks = null;
		if (action == Action.ISSUING)
			pks = request.getPublicKeyList();

		return new JwtSessionRequest(session.getJwt(), nonce, request.getContext(), pks);
	}

	public IrmaSession.Status getStatus(String sessiontoken) {
		return sessions
				.getNonNullSession(sessiontoken)
				.getStatus();
	}

	protected byte getMetadataVersion(ProtocolVersion version) {
		if (version.below(optionalAttributesProtocolBoundary)) {
			return 0x02; // does not support optional attributes
		}
		return 0x03; // current version
	}

	public void delete(String sessiontoken) {
		SessionClass session = sessions.getNonNullSession(sessiontoken);

		logger.info("Received delete, token: " + sessiontoken);
		if (session.getStatus() == IrmaSession.Status.CONNECTED) {
			// We have connected clients, we need to inform listeners of cancel
			session.setStatusCancelled();

			// If status socket is still active then the update has been sent, so we
			// can remove the session immediately. Otherwise we wait until the
			// status has been polled.
			if (session.isStatusSocketConnected()) {
				session.close();
			}
		} else {
			// In all other cases INITIALIZED, CANCELLED, DONE all parties
			// are already informed, we can close the session
			session.close();
		}
	}

	/**
	 * Removes the session, informs the identity provider, and throws an exception to notify the token.
	 * @throws ApiException The specified exception
	 */
	protected void fail(ApiError error, SessionClass session) throws ApiException {
		logger.warn("Session failed: {} {} {} {}", session.getSessionToken(), error.getStatusCode(), error.toString(), error.getDescription());
		session.setStatusCancelled();
		throw new ApiException(error);
	}
}
