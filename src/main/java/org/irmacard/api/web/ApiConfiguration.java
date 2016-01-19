package org.irmacard.api.web;

import io.jsonwebtoken.SignatureAlgorithm;
import org.irmacard.api.common.util.GsonUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;

@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "FieldCanBeLocal"})
public class ApiConfiguration {
	private static final String filename = "config.json";
	private static ApiConfiguration instance;

	/* Configuration keys and defaults */
	private String jwt_secretkey = "sk.der";
	private String jwt_publickey = "pk.der";
	private boolean enable_issuing = false;
	private ArrayList<String> issue_credentials = new ArrayList<>();
	public HashMap<String, String> idp_publickeys = new HashMap<>();

	/* Transient members for convenience */
	private transient PrivateKey jwtKey;
	private transient PublicKey jwtPKey;

	public ApiConfiguration() {}

	public static ApiConfiguration getInstance() {
		if (instance == null) {
			try {
				String json = new String(getResource(filename));
				instance = GsonUtil.getGson().fromJson(json, ApiConfiguration.class);
			} catch (IOException e) {
				instance = new ApiConfiguration();
			}
		}

		return instance;
	}

	public PrivateKey getJwtPrivateKey() throws KeyManagementException {
		if (jwtKey == null) {
			try {
				byte[] bytes = ApiConfiguration.getResource(jwt_secretkey);
				if (bytes == null || bytes.length == 0)
					throw new KeyManagementException("Could not read private key");

				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

				jwtKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
			} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new KeyManagementException(e);
			}
		}

		return jwtKey;
	}

	public PublicKey getJwtPublicKey() throws KeyManagementException {
		if (jwtPKey == null) {
			try {
				byte[] bytes = ApiConfiguration.getResource(jwt_publickey);
				if (bytes == null || bytes.length == 0)
					throw new KeyManagementException("Could not read public key");

				X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

				jwtPKey = KeyFactory.getInstance("RSA").generatePublic(spec);
			} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new KeyManagementException(e);
			}
		}

		return jwtPKey;
	}

	public SignatureAlgorithm getJwtAlgorithm() {
		return SignatureAlgorithm.RS256;
	}

	public boolean isIssuingEnabled() {
		return enable_issuing;
	}

	public boolean canIssueCredential(String name) {
		return issue_credentials.contains(name);
	}

	public static byte[] getResource(String filename) throws IOException {
		URL url = TokenKeyManager.class.getClassLoader().getResource(filename);
		if (url == null)
			throw new IOException("Could not load file " + filename);

		return convertSteamToByteArray(url.openStream(), 2048);
	}

	public static byte[] convertSteamToByteArray(InputStream stream, int size) throws IOException {
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
