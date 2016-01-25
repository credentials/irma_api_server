package org.irmacard.api.web;

import org.irmacard.api.common.IssuingRequest;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.api.common.IdentityProviderRequest;

public class IssueSession extends IrmaSession<IdentityProviderRequest, IssuingRequest> {
	private IssueCommitmentMessage commitments;

	public IssueSession(IdentityProviderRequest ipRequest) {
		super(ipRequest);
	}

	public IssueCommitmentMessage getCommitments() {
		return commitments;
	}

	public void setCommitments(IssueCommitmentMessage commitments) {
		this.commitments = commitments;
	}
}
