package com.microsoft.azure.oauth.api;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.model.Verb;

public class AzureActiveDirectoryApi extends DefaultApi20 {

    AzureActiveDirectoryConfig config;
    public AzureActiveDirectoryApi(AzureActiveDirectoryConfig config) {
        this.config = config;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return String.format(OAUTH_ENDPOINT_PATTERN + "token/", TENANT);
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {

    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

}