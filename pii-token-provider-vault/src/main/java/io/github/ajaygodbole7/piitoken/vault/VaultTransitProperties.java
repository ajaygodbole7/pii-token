package io.github.ajaygodbole7.piitoken.vault;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties("pii.vault")
public final class VaultTransitProperties {

    private URI address;
    private String namespace;
    private String mount = "transit";
    private String keyName;
    private String keySetId;
    private String currentVersion;
    private Map<String, Integer> versions = new LinkedHashMap<>();
    private Duration totalDeadline = Duration.ofSeconds(3);
    private Duration retryDelay = Duration.ofMillis(25);
    private int maxAttempts = 2;
    private int maxConcurrency = 32;
    private boolean allowInsecureHttp;

    public URI getAddress() {
        return address;
    }

    public void setAddress(URI address) {
        this.address = address;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getMount() {
        return mount;
    }

    public void setMount(String mount) {
        this.mount = mount;
    }

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public String getKeySetId() {
        return keySetId;
    }

    public void setKeySetId(String keySetId) {
        this.keySetId = keySetId;
    }

    public String getCurrentVersion() {
        return currentVersion;
    }

    public void setCurrentVersion(String currentVersion) {
        this.currentVersion = currentVersion;
    }

    public Map<String, Integer> getVersions() {
        return versions;
    }

    public void setVersions(Map<String, Integer> versions) {
        this.versions = versions;
    }

    public Duration getTotalDeadline() {
        return totalDeadline;
    }

    public void setTotalDeadline(Duration totalDeadline) {
        this.totalDeadline = totalDeadline;
    }

    public Duration getRetryDelay() {
        return retryDelay;
    }

    public void setRetryDelay(Duration retryDelay) {
        this.retryDelay = retryDelay;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    public int getMaxConcurrency() {
        return maxConcurrency;
    }

    public void setMaxConcurrency(int maxConcurrency) {
        this.maxConcurrency = maxConcurrency;
    }

    public boolean isAllowInsecureHttp() {
        return allowInsecureHttp;
    }

    public void setAllowInsecureHttp(boolean allowInsecureHttp) {
        this.allowInsecureHttp = allowInsecureHttp;
    }
}
