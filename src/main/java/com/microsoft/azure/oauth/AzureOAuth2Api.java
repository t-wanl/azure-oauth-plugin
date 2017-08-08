package com.microsoft.azure.oauth;

/**
 * Created by t-wanl on 8/8/2017.
 */

import com.google.gson.Gson;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Google OAuth2.0 Released under the same license as scribe (MIT License)
 *
 * @author yincrash
 *
 */
public class AzureOAuth2Api extends DefaultApi20 {

    public static final Gson GSON = new Gson();
    private static final String ENDPOINT = "https://login.microsoftonline.com/common/oauth2/";

    private static final String AUTHORIZE_URL = ENDPOINT + "authorize?" +
            "client_id=%s" +
            "&response_type=code" +
            "&redirect_uri=%s" +
            "&response_mode=query";

    private static final String ACCESS_TOKEN_ENDPOINT = ENDPOINT + "token/";

    private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL + "&scope=%s";

    public static String getENDPOINT() {
        return ENDPOINT;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return ACCESS_TOKEN_ENDPOINT;
    }
 
    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new AccessTokenExtractor() {

            @Override
            public Token extract(String response) {
                Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");

                Matcher matcher = Pattern.compile("\"access_token\" : \"([^&\"]+)\"").matcher(response);
                if (matcher.find()) {
                    String token = OAuthEncoder.decode(matcher.group(1));
                    return new Token(token, "", response);
                } else {
                    throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
                }
            }


        };
    }



//    public AzureUser getUserByToken(Token accessToken) {
////        OAuthRequest request = new OAuthRequest(Verb.GET, ENDPOINT + "user");
////        service.signRequest(accessToken, request);
////        Response response = request.send();
////        String json = response.getBody();
////        Gson GSON = new Gson();
////        BitbucketUserResponce userResponce = GSON.fromJson(json, BitbucketUserResponce.class);
////        if (userResponce != null) {
////            return userResponce.user;
////        } else {
////            return null;
////        }
//
//    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {
        return String.format(AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
    }
 
    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }
 
    @Override
    public OAuthService createService(OAuthConfig config) {
        return new AzureOAuth2Service(this, config);
    }
 


 
}