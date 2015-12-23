/*
 * VerificationResource.java
 *
 * Copyright (c) 2015, Wouter Lueks, Radboud University
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

import javax.websocket.CloseReason;
import javax.websocket.OnClose;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.RemoteEndpoint;
import javax.websocket.Session;
import javax.websocket.server.PathParam;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/api/v1/status/{sessionToken}")
public class StatusSocket {

    private Session session;
    private RemoteEndpoint.Async remote;
    private VerificationSessions sessions = VerificationSessions.getInstance();

    @OnClose
    public void onWebSocketClose(CloseReason closeReason) {
        this.session = null;
        this.remote = null;
        System.out.println("WebSocket Close: " + closeReason.getCloseCode() + " "
                + closeReason.getReasonPhrase());
    }

    @OnOpen
    public void onWebSocketOpen(Session session,
            @PathParam("sessionToken") String sessionToken) {
        this.session = session;
        this.remote = this.session.getAsyncRemote();

        // Prevent websockets from being closed prematurely.
        session.setMaxIdleTimeout(0);

        System.out.println("WebSocket Connect: " + session);

        // Store websocket connection in the corresponding session
        VerificationSession vsession = sessions.getSession(sessionToken);
        if (vsession == null) {
            // TODO: Add some error handling here
            System.out.println("Strange verification not yet setup");
        } else {
            vsession.setStatusSocket(this);
        }
    }

    /**
     * Messages sent by the client are not supported
     *
     * @param message
     *            The client-message
     * @param sessionToken
     *            The url-supplied sessionToken
     */
    @OnMessage
    public void onMessage(String message, @PathParam("sessionToken") String sessionToken) {
        System.out.println("Received message from client: " + message);

        if (this.session != null && this.session.isOpen() && this.remote != null) {
            this.remote.sendText("NOT SUPPORTED");
        }
    }

    /**
     * Informs the client-website that a token has connected to the verification
     * server.
     */
    public void sendConnected() {
        remote.sendText("CONNECTED");
    }

    /**
     * Inform the client-website that the token has completed the verification.
     */
    public void sendDone() {
        remote.sendText("DONE");
    }
}