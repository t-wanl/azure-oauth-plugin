package com.microsoft.azure.oauth;

import com.google.gson.Gson;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.scribe.model.Token;
import com.microsoft.azure.oauth.AzureUser.AzureUserResponce;


/**
 * Created by t-wanl on 8/9/2017.
 */


public class AzureAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -7826610577724673531L;

    private AzureApiToken azureApiToken;
    private AzureUser azureUser;

    public AzureAuthenticationToken(AzureApiToken azureApiToken) {
        this.azureApiToken = azureApiToken;

        Gson gson = new Gson();
        String userInfo = this.azureApiToken.getUserInfo();
        this.azureUser = gson.fromJson(userInfo, AzureUser.class);

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
     * @return the azureApiToken
     */
    public Token getAzureApiToken() {
        return azureApiToken;
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
