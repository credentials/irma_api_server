package org.irmacard.api.web;

import org.irmacard.api.common.IssuingRequest;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.api.common.IdentityProviderRequest;

public class IssueSession extends IrmaSession {
	private IdentityProviderRequest ipRequest;
	private IssuingRequest request;
	private IssueCommitmentMessage commitments;

	public IssueSession(String sessionToken, IdentityProviderRequest ipRequest) {
		super(sessionToken, ipRequest.getTimeout());
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
}
