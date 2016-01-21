package org.irmacard.api.web;

public abstract class IrmaSession {
	private String sessionToken;
	private StatusSocket statusSocket;

	public IrmaSession(String sessionToken) {
		this.sessionToken = sessionToken;
	}

	public String getSessionToken() {
		return sessionToken;
	}

	public void setStatusSocket(StatusSocket socket) {
		this.statusSocket = socket;
	}

	public void setStatusConnected() {
		if (statusSocket != null)
			statusSocket.sendConnected();
	}

	public void setStatusDone() {
		if (statusSocket != null)
			statusSocket.sendDone();
	}

	public void setStatusCancelled() {
		if (statusSocket != null)
			statusSocket.sendCancelled();
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
	 * Close the session. This also causes the socket to be closed
	 */
	public void close() {
		if (statusSocket != null)
			statusSocket.close();
	}
}
