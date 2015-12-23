/*
 * VerificationSession.java
 *
 * Copyright (c) 2015, Sietse Ringers, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.verification.web;

import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.verification.common.DisclosureProofRequest;
import org.irmacard.verification.common.DisclosureProofResult;
import org.irmacard.verification.common.ServiceProviderRequest;

public class VerificationSession {
    private String sessionToken;
    private ServiceProviderRequest spRequest;
    private DisclosureProofResult result;
    private ProofD proof;
    private Status status = Status.INITIALIZED;
    private StatusSocket statusSocket;

    public enum Status {
        INITIALIZED, CONNECTED, DONE
    };

    public VerificationSession(String sessionToken, ServiceProviderRequest spRequest) {
        this.sessionToken = sessionToken;
        this.spRequest = spRequest;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public DisclosureProofRequest getRequest() {
        return spRequest.getRequest();
    }

    public ServiceProviderRequest getServiceProviderRequest() {
        return spRequest;
    }

    public void setServiceProviderRequest(ServiceProviderRequest spRequest) {
        this.spRequest = spRequest;
    }

    public ProofD getProof() {
        return proof;
    }

    public void setProof(ProofD proof) {
        this.proof = proof;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatusSocket(StatusSocket socket) {
        this.statusSocket = socket;
    }

    public void setStatusConnected() {
        status = Status.CONNECTED;
        statusSocket.sendConnected();
    }

    public void setStatusDone() {
        status = Status.DONE;
        statusSocket.sendDone();
    }

    public DisclosureProofResult getResult() {
        return result;
    }

    public void setResult(DisclosureProofResult result) {
        this.result = result;
        setStatusDone();
    }
}
