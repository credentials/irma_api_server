package org.irmacard.api.web;

import org.irmacard.api.common.IssuingRequest;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.api.common.IdentityProviderRequest;

public class IssueSession extends IrmaSession {
	private Status status = Status.INITIALIZED;
	private IdentityProviderRequest ipRequest;
	private IssuingRequest request;
	private IssueCommitmentMessage commitments;

	public enum Status {
		INITIALIZED, CONNECTED, CANCELLED, DONE
	};

	public IssueSession(String sessionToken, IdentityProviderRequest ipRequest) {
		super(sessionToken);
		this.ipRequest = ipRequest;
		this.request = ipRequest.getRequest();
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

	@Override
	public void setStatusConnected() {
		super.setStatusConnected();
		status = Status.CONNECTED;
	}

	@Override
	public void setStatusDone() {
		super.setStatusDone();
		status = Status.DONE;
	}

	@Override
	public void setStatusCancelled() {
		super.setStatusCancelled();
		status = Status.CANCELLED;
	}
}
