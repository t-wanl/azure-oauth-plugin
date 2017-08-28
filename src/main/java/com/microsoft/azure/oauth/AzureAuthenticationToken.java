package com.microsoft.azure.oauth;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.scribe.model.Token;
import com.microsoft.azure.oauth.AzureUser.AzureUserResponce;

import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;


/**
 * Created by t-wanl on 8/9/2017.
 */


public class AzureAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 2L;

    private AzureApiToken azureApiToken;
    private AzureUser azureUser;
    public static final TimeUnit CACHE_EXPIRY = TimeUnit.HOURS;

    private static final Cache<String, Set<String>> groupsByUserId =
            CacheBuilder.newBuilder().expireAfterWrite(1, CACHE_EXPIRY).build();

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

    public AzureUser getAzureUser() {
        return azureUser;
    }

    public Set<String> getMemberGroups() throws ExecutionException {
        String userId = azureUser.getObjectID();
        System.out.println("getMemberGroups ");
        return groupsByUserId.get(userId, new Callable<Set<String>>() {
            @Override
            public Set<String> call() throws Exception {
                String accessToken = azureApiToken.getToken();
                String tenant = azureUser.getTenantID();
                String userId = azureUser.getObjectID();
                System.out.println("Get member group via azure ad api");
                return AzureAdApi.getGroupsByUserId(accessToken, tenant, userId);
            }
        });
    }
}
