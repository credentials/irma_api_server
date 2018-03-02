package org.irmacard.api.web.sessions;

public class ProtocolVersion {
    private int major;
    private int minor;

    public ProtocolVersion(int major, int minor) {
        this.major = major;
        this.minor = minor;
    }

    public ProtocolVersion(String versionString) {
        String[] parts = versionString.split("\\.");
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid version string:" + versionString + "..." + parts.length);
        }
        this.major = Integer.parseInt(parts[0]);
        this.minor = Integer.parseInt(parts[1]);
    }

    public boolean below(int major, int minor) {
        return this.major < major || this.major == major && this.minor < minor;
    }

    public String toString() {
        return major + "." + minor;
    }
}
