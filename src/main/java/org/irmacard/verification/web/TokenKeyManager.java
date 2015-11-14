/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.verification.web;

import io.jsonwebtoken.SignatureAlgorithm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class TokenKeyManager {
	private static PrivateKey key;
	private static PublicKey publicKey;

	public static PrivateKey getKey() throws KeyManagementException {
		if (key == null) {
			try {
				byte[] bytes = getResource("sk.der");
				if (bytes == null || bytes.length == 0)
					throw new KeyManagementException("Could not read private key");

				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

				key = KeyFactory.getInstance("RSA").generatePrivate(spec);
			} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new KeyManagementException(e);
			}
		}

		return key;
	}

	public static PublicKey getPublicKey() throws KeyManagementException {
		if (publicKey == null) {
			try {
				byte[] bytes = getResource("pk.der");
				if (bytes == null || bytes.length == 0)
					throw new KeyManagementException("Could not read public key");

				X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

				publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
			} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new KeyManagementException(e);
			}
		}

		return publicKey;
	}

	public static SignatureAlgorithm getAlgorithm() {
		return SignatureAlgorithm.RS256;
	}

	private static byte[] getResource(String filename) throws IOException {
		URL url = TokenKeyManager.class.getClassLoader().getResource(filename);
		if (url == null)
			throw new IOException("Could not load file " + filename);

		return convertSteamToByteArray(url.openStream(), 2048);
	}

	private static byte[] convertSteamToByteArray(InputStream stream, int size) throws IOException {
		byte[] buffer = new byte[size];
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		int line;
		while ((line = stream.read(buffer)) != -1) {
			os.write(buffer, 0, line);
		}
		stream.close();

		os.flush();
		os.close();
		return os.toByteArray();
	}
}
