package com.microsoft.azure.oauth;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by t-wanl on 8/24/2017.
 */
public class HttpHelper {
    public static HttpResponse sendGet(String url, String accessToken) throws IOException {
        HttpClient client = new DefaultHttpClient();
        HttpGet request = new HttpGet(url);

        Map<String, String> headers = generateHeaders(request, accessToken);
        request = (HttpGet) addHeaders(request, headers);
        HttpResponse response = client.execute(request);
        return response;
    }

    public static HttpResponse sendPost(String url, String accessToken, JSONObject body) throws IOException {
        HttpClient client = new DefaultHttpClient();
        HttpPost request = new HttpPost(url);

        Map<String, String> headers = generateHeaders(request, accessToken);
        request = (HttpPost) addHeaders(request, headers);
        request = addBody(request, body);
        HttpResponse response = client.execute(request);
        return response;
    }

    private static HttpPost addBody(HttpPost post, JSONObject body) throws UnsupportedEncodingException {
        post.setEntity(new StringEntity(body.toString()));
        return post;
    }

    private static Map<String, String> generateHeaders(HttpRequestBase request, String accessToken) {
        Map<String, String> headers = new HashMap<String, String>();

        if (request instanceof HttpGet) {
            headers.put("api-version", "1.6");
            headers.put("Authorization", "Bearer " + accessToken);
            headers.put("Accept", "application/json;odata=minimalmetadata");
        } else {
            headers.put("api-version", "beta");
            headers.put("Authorization", "Bearer " + accessToken);
            headers.put("Accept", "application/json, text/plain, */*");
            headers.put("Content-Type", "application/json;charset=UTF-8");
        }

        return headers;
    }
    private static HttpRequestBase addHeaders(HttpRequestBase request, Map<String, String> headers) {
        for(Map.Entry<String, String> h : headers.entrySet()) {
            String key = h.getKey();
            String val = h.getValue();
            request.addHeader(key, val);
        }
        return request;
    }

    public static int getStatusCode(HttpResponse response) {
        return response.getStatusLine().getStatusCode();
    }

    public static String getContent(HttpResponse response) throws IOException {
        BufferedReader rd = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent()));

        StringBuffer result = new StringBuffer();
        String line = "";
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }

        return result.toString();
    }

}
