package com.microsoft.azure.oauth;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.DefaultHttpClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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

    private static Map<String, String> generateHeaders(HttpRequestBase request, String accessToken) {
        Map<String, String> headers = new HashMap<String, String>();

        if (request instanceof HttpGet) {
            headers.put("api-version", "1.6");
            headers.put("Authorization", "Bearer " + accessToken);
            headers.put("Accept", "application/json;odata=minimalmetadata");
        } else {
            // TODO
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
