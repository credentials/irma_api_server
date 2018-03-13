package org.irmacard.api.web.sessions;

import org.irmacard.api.common.ClientRequest;
import org.irmacard.api.web.ApiConfiguration;
import org.irmacard.api.web.ProtocolVersion;
import org.irmacard.api.web.StatusSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Timer;
import java.util.TimerTask;

public abstract class IrmaSession<T extends ClientRequest<S>, S> {
	private static Logger logger = LoggerFactory.getLogger(IrmaSession.class);

	private String sessionToken;
	private StatusSocket statusSocket;
	private Timer timer;
	private T clientRequest;
	private String jwt;
	private ProtocolVersion version;

	private class RemovalTask extends TimerTask {
		@Override
		public void run() {
			logger.warn("Session " + sessionToken + " timeout, removing");
			if (statusSocket != null)
				statusSocket.sendTimeout();
			close();
		}
	}

	private Status status = Status.INITIALIZED;

	public enum Status {
		INITIALIZED, CONNECTED, CANCELLED, DONE
	}

	public IrmaSession() {
		this.sessionToken = Sessions.generateSessionToken();
	}

	/**
	 * Construct a new session for the specified client (IdP or SP) request.
	 * @param clientRequest The request that started this session
	 */
	public IrmaSession(T clientRequest) {
		this();
		setClientRequest(clientRequest);
	}

	private void delayRemoval(int timeout) {
		logger.info("Delaying removal of session " + sessionToken + " with " + timeout + " seconds");

		if (timer != null)
			timer.cancel();
		timer = new Timer();
		timer.schedule(new RemovalTask(), timeout * 1000);
	}

	public T getClientRequest() {
		return clientRequest;
	}

	public void setClientRequest(T clientRequest) {
		this.clientRequest = clientRequest;
		delayRemoval(clientRequest.getTimeout());
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	public ProtocolVersion getVersion() {
		return version;
	}

	public void setVersion(String version) {
		// TODO: check whether version number is supported
		this.version = new ProtocolVersion(version);
	}

	public S getRequest() {
		return clientRequest.getRequest();
	}

	public String getSessionToken() {
		return sessionToken;
	}

	public void setStatusSocket(StatusSocket socket) {
		this.statusSocket = socket;
	}

	public void setStatusConnected() {
		delayRemoval(ApiConfiguration.getInstance().getTokenResponseTimeout());
		if (statusSocket != null)
			statusSocket.sendConnected();
		status = Status.CONNECTED;
	}

	public void setStatusDone() {
		delayRemoval(ApiConfiguration.getInstance().getClientGetTimeout());
		if (statusSocket != null)
			statusSocket.sendDone();
		status = Status.DONE;
	}

	public void setStatusCancelled() {
		delayRemoval(ApiConfiguration.getInstance().getClientGetTimeout());
		if (statusSocket != null)
			statusSocket.sendCancelled();
		status = Status.CANCELLED;
	}

	public Status getStatus() {
		return status;
	}

	/**
	 * Returns whether the status socket is still connected. If it is, we can
	 * safely close it after sending a CANCELLED update.
	 *
	 * @return if the status socket is open
	 */
	public boolean isStatusSocketConnected() {
		return statusSocket != null && statusSocket.isSocketConnected();
	}

	/**
	 * Close and remove the session. This also causes the socket to be closed
	 */
	public void close() {
		logger.info("Closing session " + sessionToken);

		timer.cancel();
		Sessions.removeSession(sessionToken);

		if (statusSocket != null)
			statusSocket.close();
	}
}
