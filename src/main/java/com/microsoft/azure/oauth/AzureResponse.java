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
public class AzureResponse {
    private int statusCode;
    private int successCode;
    private String responseContent;

    public AzureResponse(HttpResponse response, int successCode) throws IOException {
        String responseContent = HttpHelper.getContent(response);
        int statusCode = HttpHelper.getStatusCode(response);
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
        if (!isSuccess()) return null;
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
        if (!isSuccess()) return null;
        JSONObject json = new JSONObject(responseContent);
        JSONArray roleList = json.getJSONArray("value");
        //get Contributer id
        for(int i = 0; i < roleList.length(); i++) {
            System.out.println("role = " + roleList.getJSONObject(i).toString());
            if (roleList.getJSONObject(i).getJSONObject("properties").getString("roleName").equals("Contributor")) {
                return roleList.getJSONObject(i).getString("id");
            }
        }
        return null;
    }

    public Map<String, String> getSubscriptions() throws JSONException {
        if (!isSuccess()) return null;
        JSONObject json = new JSONObject(responseContent);
        JSONArray subcriptionsList = json.getJSONArray("value");
        Map<String, String> subscriptions = new HashMap<String, String>();
        for (int i = 0; i < subcriptionsList.length(); i++) {
            String id = subcriptionsList.getJSONObject(i).getString("subscriptionId");
            String name = subcriptionsList.getJSONObject(i).getString("displayName");
            subscriptions.put(id, name);
        }
        return subscriptions;
    }

    public Set<String> getGroupsByUserId() throws JSONException {
        if (!isSuccess()) return null;
        JSONObject json = new JSONObject(responseContent);
        JSONArray groups = json.getJSONArray("value");

        Set<String> groupId = new HashSet<String>();
        for (int i = 0; i < groups.length(); i++) {
            String aadGroupId = groups.getString(i);
            groupId.add(aadGroupId);
        }
        Utils.TimeUtil.setEndDate();
        System.out.println("time for getGroupsByUserId = " + Utils.TimeUtil.getTimeDifference() + " ms");
        return groupId;
    }
}