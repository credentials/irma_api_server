package org.irmacard.api.web.resources;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import io.jsonwebtoken.*;
import org.irmacard.api.common.*;
import org.irmacard.api.common.JwtParser;
import org.irmacard.api.common.disclosure.ServiceProviderRequest;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.issuing.IdentityProviderRequest;
import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.common.signatures.SignatureClientRequest;
import org.irmacard.api.common.signatures.SignatureProofRequest;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.sessions.*;
import org.irmacard.credentials.info.IssuerIdentifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyManagementException;
import java.util.Calendar;
import java.util.HashMap;

public abstract class BaseResource
		<RequestClass extends SessionRequest,
		ClientClass extends ClientRequest<RequestClass>,
		SessionClass extends IrmaSession<ClientClass, RequestClass>> {

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

		System.out.println("Received session, token: " + token);
		System.out.println(request.toString());

		return new ClientQr("2.0", "2.1", token, action.name().toLowerCase());
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

		// Only relevant for issuing
		HashMap<IssuerIdentifier, Integer> pks = null;
		if (action == Action.ISSUING)
			pks = request.getPublicKeyList();

		return new JwtSessionRequest(session.getJwt(), nonce, request.getContext(), pks);
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

	/**
	 * Obtain a signed JWT containing the Irma session status
	 * @param sessiontoken
	 * @return
	 * @throws KeyManagementException
	 */
	public String getStatusJwt(String sessiontoken) throws KeyManagementException {
		Calendar now = Calendar.getInstance();
		Calendar expiry = Calendar.getInstance();

		// Using client_get_timeout as default validity for sending result to callback
		int validity = ApiConfiguration.getInstance().getClientGetTimeout();

		expiry.add(Calendar.SECOND, validity);

		HashMap<String, Object> claims = new HashMap<>(3);
		claims.put("status", getStatus(sessiontoken).toString());

		JwtBuilder builder = Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(now.getTime())
				.setExpiration(expiry.getTime())
				.setSubject("irma_status");

		String jwt_issuer = ApiConfiguration.getInstance().getJwtIssuer();
		if (jwt_issuer != null)
			builder = builder.setIssuer(jwt_issuer);

		return builder
				.signWith(ApiConfiguration.getInstance().getJwtAlgorithm(),
						ApiConfiguration.getInstance().getJwtPrivateKey())
				.compact();
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

	protected static void sendProofResult(final String stringUrl , final String jwt) {
		final URL url;
		try {
			url = new URL(stringUrl);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return;
		}

		final HttpTransport transport = new NetHttpTransport.Builder().build();
		final HttpContent content = new ByteArrayContent("text/plain", jwt.getBytes());

		new Thread() {
			@Override
			public void run() {
				try {
					HttpRequest proofResultRequest = transport.createRequestFactory().buildPostRequest(new GenericUrl(url), content);
					HttpResponse response = proofResultRequest.execute();
					System.out.println("Result sent to callbackURL, result: " + new BufferedReader(new InputStreamReader(response.getContent())).readLine());
				} catch (HttpResponseException e) {
					System.out.println("Sending to callbackURL failed!");
					System.out.println(e.getMessage());
				} catch (IOException e) {
					e.printStackTrace();
				}

			}
		}.start();
	}

	/**
	 * Removes the session, informs the identity provider, and throws an exception to notify the token.
	 * @throws ApiException The specified exception
	 */
	protected void fail(ApiError error, SessionClass session) throws ApiException {
		String sessiontoken = session.getSessionToken();
		session.setStatusCancelled();
		if (session.getClientRequest().getCallbackUrl() != null) {
			String callbackUrl = session.getClientRequest().getCallbackUrl() + "/" + sessiontoken;
			System.out.println("Posting failure status to: " + callbackUrl);

			try {
				sendProofResult(callbackUrl, getStatusJwt(sessiontoken));
			} catch (KeyManagementException e) {
				e.printStackTrace();
			}
		}
		throw new ApiException(error);
	}
}
