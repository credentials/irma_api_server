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
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.sessions.*;

import java.math.BigInteger;
import java.security.Key;

public abstract class BaseResource
		<RequestClass extends SessionRequest,
		ClientClass extends ClientRequest<RequestClass>,
		SessionClass extends IrmaSession<ClientClass, RequestClass>> {

	/* Template boilerplate to keep the type system happy. Getting rather crazy here,
	 * but the code deduplication is worth it. (Would be entirely unnecessary if Java
	 * didn't have runtime type erasure...) */

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
		if (ApiConfiguration.getInstance().isHotReloadEnabled())
			ApiConfiguration.load();

		@SuppressWarnings("unchecked")
		JwtParser<ClientClass> parser = (JwtParser<ClientClass>) new JwtParser<>(action.ClientClass,
				ApiConfiguration.getInstance().allowUnsignedRequests(action),
				ApiConfiguration.getInstance().getMaxJwtAge());

		parser.setKeyResolver(new SigningKeyResolverAdapter() {
			@Override public Key resolveSigningKey(JwsHeader header, Claims claims) {
				String keyId = (String) header.get("kid");
				if (keyId == null)
					keyId = claims.getIssuer();
				return ApiConfiguration.getInstance().getClientPublicKey(action, keyId);
			}
		});

		ClientClass request = parser.parseJwt(jwt).getPayload();
		return create(request, parser.getJwtIssuer(), jwt);
	}

	public abstract ClientQr create(ClientClass clientRequest, String issuer, String jwt);

	public ClientQr create(SessionClass session, ClientClass clientRequest, String jwt) {
		if (clientRequest.getTimeout() == 0)
			clientRequest.setTimeout(ApiConfiguration.getInstance().getTokenGetTimeout());
		session.setClientRequest(clientRequest);

		RequestClass request = clientRequest.getRequest();
		request.setNonceAndContext();

		session.setJwt(jwt);
		String token = session.getSessionToken();
		sessions.addSession(session);

		System.out.println("Received session, token: " + token);
		System.out.println(request.toString());

		return new ClientQr("2.0", "2.1", token);
	}

	public RequestClass get(String sessiontoken) {
		System.out.println("Received get, token: " + sessiontoken);
		SessionClass session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.INITIALIZED) {
			fail(ApiError.UNEXPECTED_REQUEST, session);
		}

		session.setStatusConnected();
		return session.getRequest();
	}

	public JwtSessionRequest getJwt(String sessiontoken) {
		System.out.println("Received get, token: " + sessiontoken);
		SessionClass session = sessions.getNonNullSession(sessiontoken);
		if (session.getStatus() != IssueSession.Status.INITIALIZED) {
			fail(ApiError.UNEXPECTED_REQUEST, session);
		}

		session.setStatusConnected();
		RequestClass request = session.getRequest();
		BigInteger nonce = request.getNonce();
		if (action == Action.SIGNING)
			nonce = ((SignatureProofRequest) request).getSignatureNonce();

		return new JwtSessionRequest(session.getJwt(), nonce, request.getContext());
	}

	public IrmaSession.Status getStatus(String sessiontoken) {
		SessionClass session = sessions.getNonNullSession(sessiontoken);
		IrmaSession.Status status = session.getStatus();

		// Remove the session if this session is cancelled
		if (status == IrmaSession.Status.DONE || status == IrmaSession.Status.CANCELLED) {
			session.close();
		}

		return status;
	}

	public void delete(String sessiontoken) {
		SessionClass session = sessions.getNonNullSession(sessiontoken);

		System.out.println("Received delete, token: " + sessiontoken);
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
		session.setStatusCancelled();
		throw new ApiException(error);
	}
}
