package io.github.ajaygodbole7.piitoken.kms;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Configuration for the AWS KMS HMAC provider.
 */
@ConfigurationProperties("pii.kms")
public final class KmsHmacProperties {

    private String region;
    private URI endpointOverride;
    private boolean allowInsecureHttp;
    private String keySetId;
    private String currentVersion;
    private Map<String, String> keyArns = new LinkedHashMap<>();
    private Duration totalDeadline = Duration.ofSeconds(3);
    private Duration retryDelay = Duration.ofMillis(25);
    private int maxAttempts = 2;
    private int maxConcurrency = 32;

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public URI getEndpointOverride() {
        return endpointOverride;
    }

    public void setEndpointOverride(URI endpointOverride) {
        this.endpointOverride = endpointOverride;
    }

    public boolean isAllowInsecureHttp() {
        return allowInsecureHttp;
    }

    public void setAllowInsecureHttp(boolean allowInsecureHttp) {
        this.allowInsecureHttp = allowInsecureHttp;
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

    public Map<String, String> getKeyArns() {
        return keyArns;
    }

    public void setKeyArns(Map<String, String> keyArns) {
        this.keyArns = keyArns;
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
}
