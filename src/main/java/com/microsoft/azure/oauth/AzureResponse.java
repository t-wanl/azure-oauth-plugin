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
abstract public class AzureResponse <T> {
    private int statusCode;
    private int successCode;
    private String responseContent;
    private Object object;

    public AzureResponse(HttpResponse response, int successCode) throws IOException, JSONException {
        String responseContent = HttpHelper.getContent(response);
        int statusCode = HttpHelper.getStatusCode(response);
        this.statusCode = statusCode;
        this.successCode = successCode;
        this.responseContent = responseContent;
        this.object = null;

        if (isSuccess()) {
            this.object = perform(responseContent);
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
    public boolean isFail() {
        return !isSuccess();
    }

    public T getResult() {
        return (T) this.object;
    }






}