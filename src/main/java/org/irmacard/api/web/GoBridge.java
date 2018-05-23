package org.irmacard.api.web;

import com.google.gson.JsonSyntaxException;
import foundation.privacybydesign.common.BaseConfiguration;
import org.apache.commons.lang3.ArrayUtils;
import org.irmacard.api.common.IrmaSignedMessage;
import org.irmacard.api.common.util.GsonUtil;

import java.io.File;
import java.io.IOException;
import java.net.URL;

public class GoBridge {
	private static String executable;
	private static String irmaconfiguration;
	private static boolean enabled = false;

	static {
		try {
			URL url = GoBridge.class.getClassLoader().getResource("timestamp");
			if (url == null) throw new RuntimeException("timestamp binary not found");
			File file = new File(url.toURI());
			executable = file.getPath();
			irmaconfiguration = file.getParent() + "/irma_configuration";
			enabled = true;
		} catch (Exception e) {
			System.out.printf("Failed to initialize GoBridge: %s\n", e.getMessage());
			enabled = false;
		}
	}

	private static <T> T execute(Class<T> clazz, String... args) throws IOException, InterruptedException, IllegalStateException, JsonSyntaxException {
		if (!enabled)
			throw new IllegalStateException("GoBridge is not enabled");
		Process child = Runtime.getRuntime().exec(ArrayUtils.addAll(new String[]{executable, irmaconfiguration}, args));
		child.waitFor();
		String output = new String(BaseConfiguration.convertSteamToByteArray(child.getInputStream(), 2048));
		if (child.exitValue() != 0)
			throw new RuntimeException(GsonUtil.getGson().fromJson(output, String.class));
		return GsonUtil.getGson().fromJson(output, clazz);
	}

	public static String verifyTimestamp(IrmaSignedMessage msg) throws IOException, InterruptedException, IllegalStateException, JsonSyntaxException {
		return execute(String.class, GsonUtil.getGson().toJson(msg));
	}

	public static boolean isEnabled() {
		return enabled;
	}
}
