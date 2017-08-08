package com.microsoft.azure.oauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.scribe.model.Token;
import org.scribe.oauth.OAuthService;

public class AzureAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -7826610577724673531L;

    private Token accessToken;
    private AzureUser azureUser;

    public AzureAuthenticationToken(Token accessToken, AzureOAuth2Service service) {
        this.accessToken = accessToken;
        this.azureUser = service.getAzureUser();


        boolean authenticated = false;

        if (azureUser != null) {
            authenticated = true;
        }

        setAuthenticated(authenticated);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return this.azureUser != null ? this.azureUser.getAuthorities() : new GrantedAuthority[0];
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
        return (azureUser != null ? azureUser.getUsername() : null);
    }

}
