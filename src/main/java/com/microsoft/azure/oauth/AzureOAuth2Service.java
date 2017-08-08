package com.microsoft.azure.oauth;

import com.google.gson.Gson;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.*;
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
 * Created by t-wanl on 8/8/2017.
 */
public class AzureOAuth2Service extends OAuth20ServiceImpl {
    private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    private static final String GRANT_TYPE = "grant_type";
    private DefaultApi20 api;
    private OAuthConfig config;
    public static final Gson GSON = new Gson();
    private OAuthService service;

    public AzureOAuth2Service(DefaultApi20 api, OAuthConfig config) {
        super(api, config);
        this.api = api;
        this.config = config;

        this.service = new ServiceBuilder().provider(AzureOAuth2Api.class).apiKey(config.getApiKey())
                .apiSecret(config.getApiSecret()).callback(config.getCallback()).build();
    }

    private Response response;

    @Override
    public Token getAccessToken(Token requestToken, Verifier verifier) {
        OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(),
                api.getAccessTokenEndpoint());
        switch (api.getAccessTokenVerb()) {
            case POST:
                request.addBodyParameter(OAuthConstants.CLIENT_ID,
                        config.getApiKey());
                request.addBodyParameter(OAuthConstants.CLIENT_SECRET,
                        config.getApiSecret());
                request.addBodyParameter(OAuthConstants.CODE,
                        verifier.getValue());
                request.addBodyParameter(OAuthConstants.REDIRECT_URI,
                        config.getCallback());
                request.addBodyParameter(GRANT_TYPE,
                        GRANT_TYPE_AUTHORIZATION_CODE);
                break;
            case GET:
            default:
                request.addQuerystringParameter(OAuthConstants.CLIENT_ID,
                        config.getApiKey());
                request.addQuerystringParameter(OAuthConstants.CLIENT_SECRET,
                        config.getApiSecret());
                request.addQuerystringParameter(OAuthConstants.CODE,
                        verifier.getValue());
                request.addQuerystringParameter(OAuthConstants.REDIRECT_URI,
                        config.getCallback());
                if (config.hasScope())
                    request.addQuerystringParameter(OAuthConstants.SCOPE,
                            config.getScope());
        }
        this.response = request.send();
        return api.getAccessTokenExtractor().extract(this.response.getBody());


    }


    public String base64UrlDecode(String input) {
        String result = null;
        Base64 decoder = new Base64(true);
        byte[] decodedBytes = decoder.decode(input);
        result = new String(decodedBytes);
        return result;
    }

    public AzureUser getAzureUser() {
        Preconditions.checkEmptyString(this.response.getBody(), "Response body is incorrect. Can't extract a token from an empty string");

        Matcher matcher = Pattern.compile("\"id_token\" : \"([^&\"]+)\"").matcher(this.response.getBody());
        if (matcher.find()) {
            String token = OAuthEncoder.decode(matcher.group(1));
            String parts[] = token.split("\\.");
            AzureUser userResponse = GSON.fromJson(base64UrlDecode(parts[1]), AzureUser.class);
            return userResponse;
        } else {
            throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + this.response.getBody() + "'", null);
        }

    }

//    public UserDetails getUserByUsername(String username) {
//        InputStreamReader reader = null;
//        AzureUser.AzureUserResponce userResponce = null;
//        try {
//            URL url = new URL(api.getENDPOINT() + "users/" + username);
//            reader = new InputStreamReader(url.openStream(), "UTF-8");
//            Gson gson = new Gson();
//            userResponce = gson.fromJson(reader, AzureUser.AzureUserResponce.class);
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        } catch (MalformedURLException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } finally {
//            IOUtils.closeQuietly(reader);
//        }
//
//        if (userResponce != null) {
//            return userResponce.user;
//        } else {
//            return null;
//        }
//    }
}
