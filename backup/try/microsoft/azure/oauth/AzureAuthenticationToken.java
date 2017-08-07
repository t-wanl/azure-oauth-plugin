package com.microsoft.azure.oauth;

import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.scribe.model.Token;

/**
 * Created by t-wanl on 8/7/2017.
 */
public class AzureAuthenticationToken extends AbstractAuthenticationToken {
    private Token accessToken;

    public AzureAuthenticationToken(Token accessToken, String apiKey, String apiSecret) {
        this.accessToken = accessToken;
        this.bitbucketUser = new BitbucketApiService(apiKey, apiSecret).getUserByToken(accessToken);

    }
}
