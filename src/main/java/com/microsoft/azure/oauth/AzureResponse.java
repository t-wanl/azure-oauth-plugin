package com.microsoft.azure.oauth;

import org.apache.http.HttpResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.*;

/**
 * Created by t-wanl on 9/1/2017.
 */
abstract public class AzureResponse {
    private int statusCode;
    private int successCode;
    private String responseContent;
    private Object result;

    public AzureResponse(HttpResponse response, int successCode) throws IOException, JSONException {
        String responseContent = HttpHelper.getContent(response);
        int statusCode = HttpHelper.getStatusCode(response);
        this.statusCode = statusCode;
        this.successCode = successCode;
        this.responseContent = responseContent;
        this.result = null;

        if (isSuccess()) {
            this.result = perform(responseContent);
        }
    }

    abstract public Object perform(String responseContent) throws JSONException;


    public int getStatusCode() {
        return statusCode;
    }

    public int getSuccessCode() {
        return successCode;
    }

    public String getResponseContent() {
        return responseContent;
    }

    public boolean isSuccess() {
        return successCode == statusCode;
    }

    public Object getObject() {
        return this.result;
    }

    public Set toSet() {
        if (this.result instanceof Set)
            return (Set) this.result;
        return null;
    }

    public Map toMap() {
        if (this.result instanceof Map)
            return (Map) this.result;
        return null;
    }

    public String toStr() {
        if (this.result instanceof String)
            return (String) this.result;
        return null;
    }







}