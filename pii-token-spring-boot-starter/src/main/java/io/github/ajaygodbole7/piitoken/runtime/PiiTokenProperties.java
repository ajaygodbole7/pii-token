package io.github.ajaygodbole7.piitoken.runtime;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("pii")
public final class PiiTokenProperties {

    public enum SearchableDigests {
        PERMITTED,
        PROHIBITED
    }

    private String applicationNamespace;
    private SearchableDigests searchableDigests = SearchableDigests.PROHIBITED;

    public String getApplicationNamespace() {
        return applicationNamespace;
    }

    public void setApplicationNamespace(String applicationNamespace) {
        this.applicationNamespace = applicationNamespace;
    }

    public SearchableDigests getSearchableDigests() {
        return searchableDigests;
    }

    public void setSearchableDigests(SearchableDigests searchableDigests) {
        this.searchableDigests = searchableDigests;
    }

}
