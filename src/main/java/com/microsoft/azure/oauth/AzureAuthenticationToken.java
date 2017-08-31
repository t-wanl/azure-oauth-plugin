package com.microsoft.azure.oauth;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import hudson.util.FormValidation;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.json.JSONObject;
import org.scribe.model.Token;
import com.microsoft.azure.oauth.AzureUser.AzureUserResponce;

import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Created by t-wanl on 8/9/2017.
 */


public class AzureAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 2L;

    private String clientID;
    private String clientSecret;
    private AzureApiToken azureApiToken;
    private AzureUser azureUser;
    public static final TimeUnit CACHE_EXPIRY = TimeUnit.HOURS;
    private static final Logger LOGGER = Logger.getLogger(AbstractAuthenticationToken.class.getName());

    private static final Cache<String, Set<String>> groupsByUserId =
            CacheBuilder.newBuilder().expireAfterAccess(1, CACHE_EXPIRY).build();

    public AzureAuthenticationToken(AzureApiToken azureApiToken, String clientID, String clientSecret) {
        this.azureApiToken = azureApiToken;

        Gson gson = new Gson();
        String userInfo = this.azureApiToken.getUserInfo();
        this.azureUser = gson.fromJson(userInfo, AzureUser.class);

        this.clientID = clientID;
        this.clientSecret = clientSecret;

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
//                String accessToken = azureApiToken.getToken();
                String tenant = azureUser.getTenantID();
                String userId = azureUser.getObjectID();
                HttpResponse accessTokenResponce = AzureAdApi.getAppOnlyAccessTokenResponce(clientID, clientSecret, tenant);
                int statusCode = HttpHelper.getStatusCode(accessTokenResponce);
                String content = HttpHelper.getContent(accessTokenResponce);
                if (statusCode != 200) {
                    LOGGER.log(Level.SEVERE, "Cannot get app only access token!");
                    return null;
                }
                JSONObject json = new JSONObject(content);
                String accessToken = json.getString("access_token");

                System.out.println("Get member group via azure ad api");
                return AzureAdApi.getGroupsByUserId(accessToken, tenant, userId);
            }
        });
    }

}
