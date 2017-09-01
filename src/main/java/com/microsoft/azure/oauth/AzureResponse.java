package com.microsoft.azure.oauth;

import org.apache.http.HttpResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

/**
 * Created by t-wanl on 9/1/2017.
 */
class AzureResponse {
    private int statusCode;
    private int successCode;
    private String responseContent;

    public AzureResponse(int statusCode, int successCode, String responseContent) {
        this.statusCode = statusCode;
        this.successCode = successCode;
        this.responseContent = responseContent;
    }


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

    public String getServicePrincipal() throws JSONException {
        if (statusCode != 200) return null;
        JSONObject json = new JSONObject(responseContent);
        Object sp = json.get("value");
        if (sp instanceof String) {
            return ((String) sp);
        } else if (sp instanceof JSONArray){
            String oid = ((JSONArray) sp).getString(0);
            return oid;
        }
        return null;
    }

    public String getRoleId() throws JSONException {
        JSONObject json = new JSONObject(responseContent);
        JSONArray roleList = json.getJSONArray("value");
        String debugId = roleList.getJSONObject(0).getString("id");//TODO: get contributor
        return debugId;
    }
}