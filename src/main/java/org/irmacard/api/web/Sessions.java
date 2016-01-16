/*
 * VerificationSessions.java
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

package org.irmacard.api.web;

import org.bouncycastle.util.encoders.Base64;
import org.irmacard.api.web.exceptions.InputInvalidException;
import org.irmacard.api.web.exceptions.SessionUnknownException;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map.Entry;

public class Sessions<T extends IrmaSession> {
    private static Sessions<VerificationSession> vs = null;
    private static Sessions<IssueSession> is = null;
    private static final int SESSION_TOKEN_LENGTH = 33;
    private static SecureRandom rnd = new SecureRandom();

    public static Sessions<VerificationSession> getVerificationSessions() {
        if (vs == null) {
            vs = new Sessions<>();
        }
        return vs;
    }

    public static Sessions<IssueSession> getIssuingSessions() {
        if (is == null) {
            is = new Sessions<>();
        }
        return is;
    }

    private HashMap<String, T> sessions;

    public Sessions() {
        sessions = new HashMap<String, T>();
    }

    public void addSession(T session) {
        sessions.put(session.getSessionToken(), session);
    }

    public T getSession(String sessionToken) {
        return sessions.get(sessionToken);
    }

    public void remove(T session) {
        sessions.remove(session.getSessionToken());
    }

    public void print() {
        System.out.println("Active sessions:");
        for (Entry<String, T> pairs : sessions.entrySet()) {
            String key = pairs.getKey();
            IrmaSession session = pairs.getValue();

            System.out.println(key + ": " + session);
        }
    }

    /**
     * Either returns a valid, non-null session associated to the specified token, or throws an exception.
     * @throws InputInvalidException if the token is null or ""
     * @throws SessionUnknownException if there is no session corresponding to the token
     */
    public T getNonNullSession(String token) throws InputInvalidException, SessionUnknownException {
        if (token == null || token.equals(""))
            throw new InputInvalidException("Supply a valid session token");

        T session = getSession(token);
        if (session == null)
            throw new SessionUnknownException();

        return session;
    }

    /**
     * A random session token. Returns a base64 encoded string representing the
     * session token. The characters '+' and '/' are removed from this
     * representation.
     *
     * @return the random session token
     */
    public static String generateSessionToken() {
        byte[] token = new byte[SESSION_TOKEN_LENGTH];
        rnd.nextBytes(token);
        String strtoken = new String(Base64.encode(token));
        return strtoken.replace("+", "").replace("/", "");
    }
}
