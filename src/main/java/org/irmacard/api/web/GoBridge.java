package org.irmacard.api.web;

import com.google.gson.JsonSyntaxException;
import foundation.privacybydesign.common.BaseConfiguration;
import org.apache.commons.lang3.ArrayUtils;
import org.irmacard.api.common.IrmaSignedMessage;
import org.irmacard.api.common.util.GsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;

public class GoBridge {
	private static String executable;
	private static String irmaconfiguration;
	private static boolean enabled = false;

	private static final Logger logger = LoggerFactory.getLogger(GoBridge.class);
	private static final String os = System.getProperty("os.name");

	static {
		try {
			// Find the timestamp binary and our irma_configuration
			logger.info("Initializing GoBridge");
			String suffix = "";
			if (os.startsWith("Windows"))
				suffix = "-windows.exe";
			else if (os.startsWith("Mac"))
				suffix = "-macos";
			else if (os.startsWith("Linux"))
				suffix = "-linux";
			else // Warn, and try to use unsuffixed "timestamp" in this case
				logger.warn("Unrecognized operating system");
			String name = "timestamp" + suffix;

			URL url = GoBridge.class.getClassLoader().getResource(name);
			if (url == null)
				throw new RuntimeException("Binary '" + name + "' not found");
			File file = new File(url.toURI());

			irmaconfiguration = BaseConfiguration.getConfigurationDirectory().resolve("irma_configuration").getPath();
			executable = file.getPath();
			if (file.setExecutable(true) && file.canExecute())
				enabled = true;
		} catch (Exception e) {
			logger.warn("Failed to initialize GoBridge: " + e.getMessage());
			enabled = false;
		}
	}

	private static void execute(String... args)
	throws IOException, InterruptedException, IllegalStateException, JsonSyntaxException {
		if (!enabled)
			throw new IllegalStateException("GoBridge is not enabled");
		Process child = Runtime.getRuntime().exec(ArrayUtils.addAll(new String[]{executable, irmaconfiguration}, args));
		child.waitFor();
		if (child.exitValue() != 0) {
			String output = new String(BaseConfiguration.convertSteamToByteArray(child.getInputStream(), 2048));
			logger.error("Timestamp verification error: " + output);
			throw new RuntimeException(output);
		}
	}

	/**
	 * Verify the timestamp of the specified IMRA attribute-based signature, establishing that the ABS was created
	 * at the time from the timestamp, and that the IRMA attributes were valid at that time, using the irmago-based
	 * timestamp binary.
	 * NOTE: this ONLY verifies the timestamp, not the attached IRMA attributes nor that the message is validly signed.
	 * @param msg The IRMA attribute-based signature whose timestamp to verify.
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws IllegalStateException
	 * @throws JsonSyntaxException
	 */
	public static void verifyTimestamp(IrmaSignedMessage msg)
	throws IOException, InterruptedException, IllegalStateException, JsonSyntaxException {
		execute(GsonUtil.getGson().toJson(msg));
	}

	public static boolean isEnabled() {
		return enabled;
	}
}
