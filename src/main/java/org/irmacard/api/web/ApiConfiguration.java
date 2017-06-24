package org.irmacard.api.web;

import com.google.gson.JsonSyntaxException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.web.resources.BaseResource;
import org.irmacard.api.web.resources.IssueResource;
import org.irmacard.api.web.resources.SignatureResource;
import org.irmacard.api.web.resources.VerificationResource;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;

// TODO: sanity check on configuration values

@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "FieldCanBeLocal", "unused"})
public class ApiConfiguration {
	private static Logger logger = LoggerFactory.getLogger(ApiConfiguration.class);

	private static URI confPath;

	/* The 'private' modifier is purposefully absent for some of these members so that
	 * the unit tests from the same package can modify them. */
	static final String filename = "config.json";
	static final String envPrefix = "IRMA_API_CONF_";
	static ApiConfiguration instance;

	public static transient boolean testing = false;

	/* Configuration keys and defaults */
	boolean hot_reload_configuration = true;

	private String jwt_privatekey = "sk.der";
	private String jwt_publickey = "pk.der";
	private String jwt_issuer = null;

	boolean enable_verification = true;
	boolean enable_issuing = false;
	boolean enable_signing = false;

	boolean reject_unfloored_validity_timestamps = true;

	boolean allow_unsigned_issue_requests = false;
	boolean allow_unsigned_verification_requests = false;
	boolean allow_unsigned_signature_requests = false;

	int max_jwt_age = 60;
	int token_response_timeout = 10 * 60;
	int token_get_timeout = 2 * 60;
	int client_get_timeout = 2 * 60;

	HashMap<String, ArrayList<String>> authorized_idps = new HashMap<>();
	HashMap<String, ArrayList<String>> authorized_sps = new HashMap<>();
	HashMap<String, ArrayList<String>> authorized_sigclients = new HashMap<>();

	HashMap<String, String> client_names = new HashMap<>();

	/* Transient members for convenience */
	private transient PrivateKey jwtPrivateKey;
	private transient PublicKey jwtPublicKey;

	public ApiConfiguration() {}

	/**
	 * Reloads the configuration from disk so that {@link #getInstance()} returns the updated version
	 */
	public static void load() {
		// GSon seems to always be lenient (i.e. allow comments in the JSon), even though
		// the documentation states that by default, it is not lenient.
		try {
			String json = new String(getResource(filename));
			instance = GsonUtil.getGson().fromJson(json, ApiConfiguration.class);
		} catch (IOException|JsonSyntaxException e) {
			logger.info("WARNING: could not load configuration file. Using default values or environment vars");
			instance = new ApiConfiguration();
		}
		instance.loadEnvVars();

		logger.info("Configuration:");
		logger.info(instance.toString());
	}

	public static ApiConfiguration getInstance() {
		if (instance == null)
			load();

		return instance;
	}

	/**
	 * Override configuration with environment variables, if set
	 * Uses reflection to set variables, because otherwise it would be impossible to set all variable at once in a loop
	 */
	public void loadEnvVars() {
			for (Field f : this.getClass().getDeclaredFields()) {
				if ( Modifier.isTransient(f.getModifiers()) || Modifier.isStatic(f.getModifiers())) {
					// Skip transient and static fields
					continue;
				}

				Object envValue = getEnv(envPrefix + f.getName(), f.getType());
				if (envValue != null) {
					try {
						f.set(this, envValue);
					} catch (IllegalAccessException e) {
						e.printStackTrace();
					}
				}
			}
	}

	/**
	 * Obtain an environment variable and parse it to the right type
	 * @param confEntry name of environment variable
	 * @param cls class to be parsed into (either Integer, Boolean, String, HashMap)
	 * @param <T> type of the variable
	 * @return a parsed variable in the right type (T) or null if environment variable isn't set
	 */
	public static <T> T getEnv(String confEntry, Class<T> cls) {
		confEntry = confEntry.toUpperCase();
		String env = System.getenv(confEntry);
		if (env== null || env.length() == 0) {
			return null;
		}

		T overrideValue;
		if (cls == int.class) {
			try {
				Integer parsed = Integer.parseInt(env);
				overrideValue = (T) parsed;
			} catch (NumberFormatException e) {
				logger.warn("Could not parse config entry as int: " + confEntry + " with value: " + env);
				return null;
			}
		} else if (cls == boolean.class) {
			Boolean parsed = Boolean.parseBoolean(env);
			overrideValue = (T) parsed;
		} else if (cls == String.class) {
			overrideValue = cls.cast(env);
		} else if (cls == HashMap.class){ // Try to parse as hashmap for authorized_??? entries
			try {
				overrideValue = cls.cast(GsonUtil.getGson().fromJson(env, cls));
			} catch (JsonSyntaxException e) {
				logger.warn("Could not parse config entry as json: " + confEntry + " with value: " + env);
				return null;
			}
		} else {
			throw new IllegalArgumentException("Invalid class specified, must be one of: Integer, Boolean, String, HashMap");
		}

		logger.info("Overriding config entry " + confEntry + " with value: " + env);
		return overrideValue;
	}

	public SignatureAlgorithm getJwtAlgorithm() {
		return SignatureAlgorithm.RS256;
	}

	public boolean isEnabled(Class clazz) {
		if (clazz == IssueResource.class) return enable_issuing;
		if (clazz == VerificationResource.class) return enable_verification;
		if (clazz == SignatureResource.class) return enable_signing;

		throw new IllegalArgumentException("Unknown resource " + clazz.getName());
	}

	public boolean canRequestSignatureWithAttribute(String sigclient, AttributeIdentifier attribute) {
		return canRequestAttribute(sigclient, attribute, authorized_sigclients);
	}

	public boolean canVerifyAttribute(String sp, AttributeIdentifier attribute) {
		return canRequestAttribute(sp, attribute, authorized_sps);
	}

	private boolean canRequestAttribute(String client, AttributeIdentifier attribute,
	                                    HashMap<String, ArrayList<String>> authorizedClients) {
		if (!authorizedClients.containsKey(client))
			return false;

		ArrayList<String> attributes = authorizedClients.get(client);

		// This SP can verify anything
		return attributes.contains("*")
				// This SP can verify everything from this scheme manager
				|| attributes.contains(attribute.getSchemeManagerName() + ".*")
				// This SP can verify any credential from the specified issuer
				|| attributes.contains(attribute.getIssuerIdentifier() + ".*")
				// This SP can verify any attribute from the specified credential
				|| attributes.contains(attribute.getCredentialIdentifier() + ".*")
				// The attribute is explicitly listed
				|| attributes.contains(attribute.toString());
	}

	public boolean canIssueCredential(String idp, CredentialIdentifier credential) {
		if (!authorized_idps.containsKey(idp))
			return false;

		ArrayList<String> credentials = authorized_idps.get(idp);

		// This IDP can issue everything
		return credentials.contains("*")
				// This IDP can issue everything from this scheme manager
				|| credentials.contains(credential.getSchemeManagerName() + ".*")
				// This IDP can issue everything from the specified issuer
				|| credentials.contains(credential.getIssuerIdentifier() + ".*")
				// The credential is explicitly listed
				|| credentials.contains(credential.toString());
	}

	public boolean shouldRejectUnflooredTimestamps() {
		return reject_unfloored_validity_timestamps;
	}

	public int getMaxJwtAge() {
		return max_jwt_age * 1000;
	}

	public boolean allowUnsignedIssueRequests() {
		return allow_unsigned_issue_requests;
	}

	public boolean allowUnsignedVerificationRequests() {
		return allow_unsigned_verification_requests;
	}

	public boolean allowUnsignedSignatureRequests() {
		return allow_unsigned_signature_requests;
	}

	public boolean allowUnsignedRequests(BaseResource.Action action) {
		switch (action) {
			case ISSUING: return allow_unsigned_issue_requests;
			case DISCLOSING: return allow_unsigned_verification_requests;
			case SIGNING: return allow_unsigned_signature_requests;
		}

		throw new RuntimeException("Not implemented for action " + action);
	}

	public boolean isHotReloadEnabled() {
		return hot_reload_configuration;
	}

	public int getTokenResponseTimeout() {
		return token_response_timeout;
	}

	public int getTokenGetTimeout() {
		return token_get_timeout;
	}

	public int getClientGetTimeout() {
		return client_get_timeout;
	}

	public String getClientName(String kid) {
		String name = client_names.get(kid);
		if (name == null || name.length() == 0)
			return kid;
		else
			return name;
	}

	public PublicKey getClientPublicKey(String path, String name) {
		byte[] env = getBase64ResourceByEnv("BASE64_JWT_" + path + "_" + name);
		try {
			if (env != null) {
				return getPublicKey(env);
			}
			return getPublicKey(path + "/" + name + ".der");
		} catch (KeyManagementException e) {
			throw new WebApplicationException("No public key for identity provider " + name,
					Response.Status.UNAUTHORIZED);
		}
	}

	public PublicKey getClientPublicKey(BaseResource.Action action, String name) {
		switch (action) {
			case ISSUING: return getClientPublicKey("issuers", name);
			case DISCLOSING: return getClientPublicKey("verifiers", name);
			case SIGNING: return getClientPublicKey("sigclients", name);
		}

		throw new RuntimeException("Not implemented for action " + action);
	}

	/**
	 * Gets the public key of the keyshare server of the specified scheme manager
	 */
	public PublicKey getKssPublicKey(String schemeManager) {
		try {
			return getPublicKey(schemeManager + "-kss.der");
		} catch (KeyManagementException e) {
			throw new RuntimeException(e);
		}
	}

	public PrivateKey getPrivateKey(String filename) throws KeyManagementException {
		try {
			return getPrivateKey(ApiConfiguration.getResource(filename));
		} catch (IOException e) {
			throw new KeyManagementException(e);
		}
	}

	public PrivateKey getPrivateKey(byte[] bytes) throws KeyManagementException {
		try {
			if (bytes == null || bytes.length == 0)
				throw new KeyManagementException("Could not read private key");

			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

			return KeyFactory.getInstance("RSA").generatePrivate(spec);
		} catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
			throw new KeyManagementException(e);
		}
	}

	public PublicKey getJwtPublicKey() throws KeyManagementException {
		if (jwtPublicKey == null) {
			byte[] env = getBase64ResourceByEnv("BASE64_JWT_PUBLICKEY");
			if (env != null) {
				jwtPublicKey = getPublicKey(env);
			} else {
				jwtPublicKey = getPublicKey(jwt_publickey);
			}
		}

		return jwtPublicKey;
	}

	public PrivateKey getJwtPrivateKey() throws KeyManagementException {
		if (jwtPrivateKey == null) {
			byte[] env = getBase64ResourceByEnv("BASE64_JWT_PRIVATEKEY");
			if (env != null) {
				jwtPrivateKey = getPrivateKey(env);
			} else {
				jwtPrivateKey = getPrivateKey(jwt_privatekey);
			}
		}

		return jwtPrivateKey;
	}

	public String getJwtIssuer() {
		return jwt_issuer;
	}

	private PublicKey getPublicKey(String filename) throws KeyManagementException {
		try {
			return getPublicKey(ApiConfiguration.getResource(filename));
		} catch (IOException e) {
			throw new KeyManagementException(e);
		}
	}

	private PublicKey getPublicKey(byte[] bytes) throws KeyManagementException {
		try {
			if (bytes == null || bytes.length == 0)
				throw new KeyManagementException("Could not read public key");

			X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

			return KeyFactory.getInstance("RSA").generatePublic(spec);
		} catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
			throw new KeyManagementException(e);
		}
	}

	public static byte[] getResource(String filename) throws IOException {
		File file = new File(getConfigurationPath().resolve(filename));
		return convertSteamToByteArray(new FileInputStream(file), 2048);
	}

	public static byte[] getBase64ResourceByEnv(String envName) {
		String env = System.getenv(envPrefix + envName.toUpperCase());
		if (env == null || env.length() == 0) {
			return null;
		}
		return Base64.decodeBase64(env.getBytes());
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

	//region Determining configuration path

	/**
	 * Returns true if the specified path is a valid configuration directory. Currently a directory
	 * is considered a valid configuration directory if it contains a subdir called irma_configuration.
	 */
	public static boolean isConfDirectory(URI candidate) {
		if (candidate == null)
			return false;
		return new File(candidate.resolve("irma_configuration/")).isDirectory();
	}

	/**
	 * Depending on if we're running tests according to {@link ApiConfiguration#testing},
	 * returns either src/main/resources or src/test/resources, if it contains irma_configuration.
	 * @return URI to src/main/resources or src/test/resources if it contains irma_configuration, null otherwise
	 */
	public static URI getResourcesConfPath() throws URISyntaxException {
		// The only way to actually get the resource folder, as opposed to the classes folder,
		// seems to be to ask for an existing file or directory within the resources. That is,
		// ApiApplication.class.getClassLoader().getResource("/") or variants thereof
		// give an incorrect path. This is why we must treat this as a separate case.
		// Also, to get src/main/resources/irma_configuration one must apparently include a leading
		// slash, but not when fetching src/test/resources/irma_configuration :(

		URL url = ApiApplication.class.getClassLoader().getResource(
				(ApiConfiguration.testing ? "" : "/") + "irma_configuration/");
		if (url != null) // Construct an URI of the parent path
			return new URI("file://" + new File(url.getPath()).getParent() + "/");
		else
			return null;
	}

	/**
	 * If a path was set in the IRMA_API_CONF environment variable, return it
	 */
	public static URI getEnvVariableConfPath() throws URISyntaxException {
		String envPath = System.getenv("IRMA_API_CONF");
		if (envPath == null || envPath.length() == 0)
			return null;

		if (!envPath.startsWith("file://"))
			envPath = "file://" + envPath;
		if (!envPath.endsWith("/"))
			envPath += "/";

		return new URI(envPath);
	}

	/**
	 * Get the configuration directory.
	 * @throws IllegalStateException If no suitable configuration directory was found
	 * @throws IllegalArgumentException If the path from the IRMA_API_CONF environment variable was
	 *                                  not a valid path
	 */
	public static URI getConfigurationPath() throws IllegalStateException, IllegalArgumentException {
		if (confPath != null)
			return confPath;

		try {
			URI resourcesCandidate = getResourcesConfPath();

			// If we're running unit tests, only accept src/test/resources
			if (ApiConfiguration.testing) {
				if (resourcesCandidate != null) {
					confPath = resourcesCandidate;
					return confPath;
				}
				else
					throw new IllegalStateException("irma_configuration not found in src/test/resources. " +
							"(Have you run `git submodule init && git submodule update`?)");
			}

			// If we're here, we're not running unit tests.
			// If a path was given in the IRMA_API_CONF environment variable, prefer it
			URI envCandidate = getEnvVariableConfPath();
			if (envCandidate != null) {
				if (isConfDirectory(envCandidate)) {
					confPath = envCandidate;
					return confPath;
				} else {
					// If the user specified an incorrect path (s)he will want to know, so bail out here
					throw new IllegalArgumentException("Specified path in IRMA_API_CONF is not " +
							"a valid configuration directory");
				}
			}

			// See if a number of other fixed candidates are suitable
			ArrayList<URI> candidates = new ArrayList<>(4);
			candidates.add(resourcesCandidate);
			candidates.add(new URI("file:///etc/irma_api_server/"));
			candidates.add(new URI("file:///C:/irma_api_server/"));
			candidates.add(new File(System.getProperty("user.home")).toURI().resolve("irma_api_server/"));

			for (URI candidate : candidates) {
				if (isConfDirectory(candidate)) {
					confPath = candidate;
					return confPath;
				}
			}

			throw new IllegalStateException("irma_configuration not found in any of the possible " +
					"configuration directories. See README.md for more information.");
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}

		//endregion
	}
}
