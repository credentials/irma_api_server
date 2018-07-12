package org.irmacard.api.web;

import foundation.privacybydesign.common.BaseConfiguration;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.irmacard.api.web.resources.BaseResource;
import org.irmacard.api.web.resources.IssueResource;
import org.irmacard.api.web.resources.SignatureResource;
import org.irmacard.api.web.resources.VerificationResource;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;

// TODO: sanity check on configuration values

@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "FieldCanBeLocal", "unused"})
public class ApiConfiguration extends BaseConfiguration<ApiConfiguration> {
	private static Logger logger = LoggerFactory.getLogger(ApiConfiguration.class);

	static {
		BaseConfiguration.clazz = ApiConfiguration.class;
		BaseConfiguration.environmentVarPrefix = "IRMA_API_CONF_";
		BaseConfiguration.confDirEnvironmentVarName = "IRMA_API_CONF";
		BaseConfiguration.logger = ApiConfiguration.logger;
		BaseConfiguration.confDirName = "irma_api_server";
		BaseConfiguration.printOnLoad = true;
	}

	/* Configuration keys and defaults */
	public String jwt_privatekey = "sk.der";
	public String jwt_publickey = "pk.der";
	public String schemeManager_publickey = "schemeManager.pk.pem";
	public String jwt_issuer = null;

    public String client_ip_header = null;

	public boolean enable_verification = true;
	public boolean enable_issuing = false;
	public boolean enable_signing = false;

	public boolean reject_unfloored_validity_timestamps = true;

	public boolean allow_unsigned_issue_requests = false;
	public boolean allow_unsigned_verification_requests = false;
	public boolean allow_unsigned_signature_requests = false;

	public int max_jwt_age = 60;
	public int token_response_timeout = 10 * 60;
	public int token_get_timeout = 2 * 60;
	public int client_get_timeout = 2 * 60;

	public HashMap<String, ArrayList<String>> authorized_idps = new HashMap<>();
	public HashMap<String, ArrayList<String>> authorized_sps = new HashMap<>();
	public HashMap<String, ArrayList<String>> authorized_sigclients = new HashMap<>();

	public HashMap<String, String> client_names = new HashMap<>();

	public String events_webhook_uri = null;
	public String events_webhook_authorizationToken = null;

	public String schemeManager_update_uri = null;

	/* Transient members for convenience */
	private transient PrivateKey jwtPrivateKey;
	private transient PublicKey jwtPublicKey;

	public ApiConfiguration() {}

	public static ApiConfiguration getInstance() {
		return (ApiConfiguration) BaseConfiguration.getInstance();
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
		if (!authorizedClients.containsKey(client)) {
			// If requested wildcard, and not present, return false
			if (client.equals("*"))
				return false;

			// Try again with wildcard if we haven't tried that yet
			return canRequestAttribute("*", attribute, authorizedClients);
		}

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
				return decodePublicKey(env);
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
			byte[] env = getBase64ResourceByEnv("BASE64_KSS_" + schemeManager);
			if (env != null) {
				return decodePublicKey(env);
			}
			return getPublicKey(schemeManager + "-kss.der");
		} catch (KeyManagementException e) {
			throw new RuntimeException(e);
		}
	}

	public PublicKey getJwtPublicKey() throws KeyManagementException {
		if (jwtPublicKey == null) {
			byte[] env = getBase64ResourceByEnv("BASE64_JWT_PUBLICKEY");
			if (env != null) {
				jwtPublicKey = decodePublicKey(env);
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
				jwtPrivateKey = decodePrivateKey(env);
			} else {
				jwtPrivateKey = getPrivateKey(jwt_privatekey);
			}
		}

		return jwtPrivateKey;
	}

	public String getJwtIssuer() {
		return jwt_issuer;
	}


	public static byte[] getBase64ResourceByEnv(String envName) {
		String env = System.getenv(environmentVarPrefix + envName.toUpperCase());
		if (env == null || env.length() == 0) {
			return null;
		}
		return Base64.decodeBase64(env.getBytes());
	}

	public String getClientIp(HttpServletRequest req) {
		String ret;
		if (this.client_ip_header != null) {
			ret = req.getHeader(this.client_ip_header);
			if (ret != null) {
				return ret;
			}
		}
		if (req == null) // happens during unit tests
			return "127.0.0.1";
		return req.getRemoteAddr();
	}

	public String getSchemeManagerPublicKeyString() {
		try {
			return new String(getResource(schemeManager_publickey));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
