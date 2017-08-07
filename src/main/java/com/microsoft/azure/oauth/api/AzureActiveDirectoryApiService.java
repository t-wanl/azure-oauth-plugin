package com.microsoft.azure.oauth.api;

import com.google.gson.Gson;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.api.BitbucketUser.BitbucketUserResponce;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.*;
import org.scribe.oauth.OAuthService;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;

public class AzureActiveDirectoryApiService {

    private static final String API_ENDPOINT = "https://api.bitbucket.org/1.0/";

    private OAuthService service;

//    public AzureActiveDirectoryApiService(String apiKey, String apiSecret) {
//        this(apiKey, apiSecret, null);
//    }
//
//    public AzureActiveDirectoryApiService(String apiKey, String apiSecret, String callback) {
//        super();
//        ServiceBuilder builder = new ServiceBuilder().provider(AzureActiveDirectoryApi.class).apiKey(apiKey).apiSecret(apiSecret);
//        if (StringUtils.isNotBlank(callback)) {
//            builder.callback(callback);
//        }
//        service = builder.build();
//    }

    public AzureActiveDirectoryApiService(AzureActiveDirectoryConfig config) {
        super();
        ServiceBuilder builder = new ServiceBuilder().provider(AzureActiveDirectoryApi.class).apiKey(config.getClientID()).apiSecret(config.getClientSecret());
        if (StringUtils.isNotBlank(config.getCallback())) {
            builder.callback(config.getCallback());
        }
        service = builder.build();
    }

    public Token createRquestToken() {
        return service.getRequestToken();
    }

    public String createAuthorizationCodeURL(Token requestToken) {
        return service.getAuthorizationUrl(requestToken);
    }

    public Token getTokenByAuthorizationCode(String code, Token requestToken) {
        Verifier v = new Verifier(code);
        return service.getAccessToken(requestToken, v);
    }

    public AzureActiveDirectoryUser getUserByToken(Token accessToken) {
        OAuthRequest request = new OAuthRequest(Verb.GET, API_ENDPOINT + "user");
        service.signRequest(accessToken, request);
        Response response = request.send();
        String json = response.getBody();
        Gson gson = new Gson();
        BitbucketUserResponce userResponce = gson.fromJson(json, BitbucketUserResponce.class);
        if (userResponce != null) {
            return userResponce.user;
        } else {
            return null;
        }
    }

    public UserDetails getUserByUsername(String username) {
        InputStreamReader reader = null;
        BitbucketUserResponce userResponce = null;
        try {
            URL url = new URL(API_ENDPOINT + "users/" + username);
            reader = new InputStreamReader(url.openStream(), "UTF-8");
            Gson gson = new Gson();
            userResponce = gson.fromJson(reader, BitbucketUserResponce.class);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(reader);
        }

        if (userResponce != null) {
            return userResponce.user;
        } else {
            return null;
        }
    }

}
