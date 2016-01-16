package org.irmacard.api.web;

import org.irmacard.api.common.IssuingRequest;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.api.common.IdentityProviderRequest;

public class IssueSession implements IrmaSession {
	private String sessionToken;
	private Status status = Status.INITIALIZED;
	private IdentityProviderRequest ipRequest;
	private IssuingRequest request;
	private IssueCommitmentMessage commitments;

	public enum Status {
		INITIALIZED, CONNECTED, DONE, ABORTED
	};

	public IssueSession(String sessionToken, IdentityProviderRequest ipRequest) {
		this.sessionToken = sessionToken;
		this.ipRequest = ipRequest;
		this.request = ipRequest.getRequest();
	}

	@Override
	public String getSessionToken() {
		return sessionToken;
	}

	public IdentityProviderRequest getIdentityProviderRequest() {
		return ipRequest;
	}

	public IssuingRequest getRequest() {
		return request;
	}

	public IssueCommitmentMessage getCommitments() {
		return commitments;
	}

	public void setCommitments(IssueCommitmentMessage commitments) {
		this.commitments = commitments;
	}

	public Status getStatus() {
		return status;
	}

	public void setStatusConnected() {
		status = Status.CONNECTED;
	}

	public void setStatusDone() {
		status = Status.DONE;
	}

	public void setStatusAborted() {
		status = Status.ABORTED;
	}
}
