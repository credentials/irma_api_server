package org.irmacard.api.web;

public abstract class IrmaSession {
	private String sessionToken;
	private StatusSocket statusSocket;

	private Status status = Status.INITIALIZED;

	public enum Status {
		INITIALIZED, CONNECTED, CANCELLED, DONE
	};

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
		status = Status.CONNECTED;
	}

	public void setStatusDone() {
		if (statusSocket != null)
			statusSocket.sendDone();
		status = Status.DONE;
	}

	public void setStatusCancelled() {
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
	 * Close the session. This also causes the socket to be closed
	 */
	public void close() {
		if (statusSocket != null)
			statusSocket.close();
	}
}
