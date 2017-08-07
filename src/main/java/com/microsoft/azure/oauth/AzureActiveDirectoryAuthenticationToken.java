package com.microsoft.azure.oauth;

import com.microsoft.azure.oauth.api.AzureActiveDirectoryApiService;
import com.microsoft.azure.oauth.api.AzureActiveDirectoryUser;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.scribe.model.Token;

public class AzureActiveDirectoryAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -7826610577724673531L;

    private Token accessToken;
    private AzureActiveDirectoryUser bitbucketUser;

    public AzureActiveDirectoryAuthenticationToken(Token accessToken, String apiKey, String apiSecret) {
        this.accessToken = accessToken;
        this.bitbucketUser = new AzureActiveDirectoryApiService(apiKey, apiSecret).getUserByToken(accessToken);

        boolean authenticated = false;

        if (bitbucketUser != null) {
            authenticated = true;
        }

        setAuthenticated(authenticated);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return this.bitbucketUser != null ? this.bitbucketUser.getAuthorities() : new GrantedAuthority[0];
    }

    /**
     * @return the accessToken
     */
    public Token getAccessToken() {
        return accessToken;
    }

    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }

    @Override
    public String getName() {
        return (bitbucketUser != null ? bitbucketUser.getUsername() : null);
    }

}
