package org.irmacard.api.web;

import com.google.gson.JsonSyntaxException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.irmacard.api.common.util.GsonUtil;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;

// TODO: sanity check on configuration values

@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "FieldCanBeLocal", "unused"})
public class ApiConfiguration {
	private static final String filename = "config.json";
	private static ApiConfiguration instance;

	/* Configuration keys and defaults */
	private boolean hot_reload_configuration = true;
	private String jwt_privatekey = "sk.der";
	private String jwt_publickey = "pk.der";
	private boolean enable_issuing = false;
	private boolean reject_unfloored_validity_timestamps = true;
	private boolean allow_unsigned_issue_requests = false;
	private int max_issue_request_age = 5;
	private HashMap<String, ArrayList<String>> authorized_idps = new HashMap<>();

	/* Transient members for convenience */
	private transient PrivateKey jwtPrivateKey;
	private transient PublicKey jwtPublicKey;

	public ApiConfiguration() {}

	/**
	 * Reloads the configuration from disk so that {@link #getInstance()} returns the updated version
	 */
	public static void load() {
		// TODO: GSon seems to always be lenient (i.e. allow comments in the JSon), even though
		// the documentation states that by default, it is not lenient. Why is this? Could change?
		try {
			String json = new String(getResource(filename));
			instance = GsonUtil.getGson().fromJson(json, ApiConfiguration.class);
		} catch (IOException|JsonSyntaxException e) {
			System.out.println("WARNING: could not load configuration file. Using default values");
			instance = new ApiConfiguration();
		}

		System.out.println("Configuration:");
		System.out.println(instance.toString());
	}

	public static ApiConfiguration getInstance() {
		if (instance == null)
			load();

		return instance;
	}

	public SignatureAlgorithm getJwtAlgorithm() {
		return SignatureAlgorithm.RS256;
	}

	public boolean isIssuingEnabled() {
		return enable_issuing;
	}

	public boolean canIssueCredential(String idp, String name) {
		if (!authorized_idps.containsKey(idp))
			return false;

		ArrayList<String> credentials = authorized_idps.get(idp);

		// This IDP can issue everything
		if (credentials.contains("*"))
			return true;

		String[] parts = name.split("\\.");
		if (parts.length != 2)
			throw new WebApplicationException("Unexpected credential identifier", Response.Status.UNAUTHORIZED);

		// This IDP can issue everything from the specified issuer
		String issuer = parts[0];
		return credentials.contains(issuer + ".*") || credentials.contains(name);
	}

	public boolean shouldRejectUnflooredTimestamps() {
		return reject_unfloored_validity_timestamps;
	}

	public int getMaxJwtAge() {
		return max_issue_request_age * 1000;
	}

	public boolean allowUnsignedJwts() {
		return allow_unsigned_issue_requests;
	}

	public boolean isHotReloadEnabled() {
		return hot_reload_configuration;
	}

	public PublicKey getIdentityProviderKey(String name) {
		try {
			return getPublicKey(name + ".der");
		} catch (KeyManagementException e) {
			throw new WebApplicationException("No public key for identity provider " + name,
					Response.Status.UNAUTHORIZED);
		}
	}

	public PrivateKey getJwtPrivateKey() throws KeyManagementException {
		if (jwtPrivateKey == null) {
			try {
				byte[] bytes = ApiConfiguration.getResource(jwt_privatekey);
				if (bytes == null || bytes.length == 0)
					throw new KeyManagementException("Could not read private key");

				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

				jwtPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
			} catch (IOException|NoSuchAlgorithmException|InvalidKeySpecException e) {
				throw new KeyManagementException(e);
			}
		}

		return jwtPrivateKey;
	}

	public PublicKey getJwtPublicKey() throws KeyManagementException {
		if (jwtPublicKey == null)
			jwtPublicKey = getPublicKey(jwt_publickey);

		return jwtPublicKey;
	}

	private PublicKey getPublicKey(String filename) throws KeyManagementException {
		try {
			byte[] bytes = ApiConfiguration.getResource(filename);
			if (bytes == null || bytes.length == 0)
				throw new KeyManagementException("Could not read public key");

			X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

			return KeyFactory.getInstance("RSA").generatePublic(spec);
		} catch (IOException|NoSuchAlgorithmException|InvalidKeySpecException e) {
			throw new KeyManagementException(e);
		}
	}

	public static byte[] getResource(String filename) throws IOException {
		URL url = ApiConfiguration.class.getClassLoader().getResource(filename);
		if (url == null)
			throw new IOException("Could not load file " + filename);

		URLConnection urlCon = url.openConnection();
		urlCon.setUseCaches(false);
		return convertSteamToByteArray(urlCon.getInputStream(), 2048);
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

	@Override
	public String toString() {
		return GsonUtil.getGson().toJson(this);
	}
}
