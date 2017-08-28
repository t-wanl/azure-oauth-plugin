package com.microsoft.azure.oauth;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.HttpResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.*;

/**
 * Created by t-wanl on 8/24/2017.
 */
public class AzureAdApi {
    /*
        get all members (user ID, user type) from group list
     */
    public static Map<String, String> getGroupMembers(List<String> groupList, String accessToken, String tenant)
            throws IOException, JSONException {
        Map<String, String> members = new HashMap<String, String>();
        for (String groupID : groupList) {
            members.putAll(getGroupMembers(groupID, accessToken, tenant, true));
        }
        return members;
    }

    /*
        get group members from single group
     */
    public static Map<String, String> getGroupMembers(String groupID, String accessToken, String tenant, boolean recursive) throws IOException, JSONException {
        Map<String, String> members = new HashMap<String, String>();

        String url = String.format("https://graph.windows.net/%s/groups/%s/members?api-version=1.6", tenant, groupID);
        HttpResponse response = HttpHelper.sendGet(url, accessToken);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray memberArray = json.getJSONArray("value");
        for (int i = 0; i < memberArray.length(); i++) {
            JSONObject member =  memberArray.getJSONObject(i);
            if (recursive && member.getString("objectType").equals("Group")) {
                String subGroupID = member.getString("objectId");
                Map<String, String> subMembers = getGroupMembers(subGroupID, accessToken, tenant, recursive);
                members.putAll(subMembers);
            } else if (member.getString("objectType").equals("User")) {
                String userID = member.getString("objectId");
                members.put(userID, "User");
            }
        }

        return members;
    }

    public static Map<String, String> getAllAadGroupsNameIdPair(String accessToken, String tenant)
            throws IOException, JSONException {
        String url = String.format("https://graph.windows.net/%s/groups?api-version=1.6", tenant);

        HttpResponse response = HttpHelper.sendGet(url, accessToken);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray groups = json.getJSONArray("value");
        Map<String, String> groupNameId = new HashMap<String, String>();
        for (int i = 0; i < groups.length(); i++) {
            String aadGroupName = groups.getJSONObject(i).getString("displayName");
            String aadGroupId = groups.getJSONObject(i).getString("objectId");
            groupNameId.put(aadGroupName, aadGroupId);
        }
        return groupNameId;
    }

    public static Set<String> getAllAadGroupsId(String accessToken, String tenant)
            throws IOException, JSONException {
        String url = String.format("https://graph.windows.net/%s/groups?api-version=1.6", tenant);

        HttpResponse response = HttpHelper.sendGet(url, accessToken);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray groups = json.getJSONArray("value");
        Set<String> groupId = new HashSet<String>();
        for (int i = 0; i < groups.length(); i++) {
            String aadGroupId = groups.getJSONObject(i).getString("objectId");
            groupId.add(aadGroupId);
        }
        return groupId;
    }

    public static Set<String> getGroups(String accessToken, String tenant, String userID) throws IOException, JSONException {
        String url = String.format("https://graph.windows.net/%s/users/%s/getMemberGroups?api-version=1.6", tenant, userID);

        JSONObject body = new JSONObject();
        body.put("securityEnabledOnly", false);
        HttpResponse response = HttpHelper.sendPost(url, accessToken, body);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray groups = json.getJSONArray("value");

        Set<String> groupId = new HashSet<String>();
        for (int i = 0; i < groups.length(); i++) {
            String aadGroupId = groups.getString(i);
            groupId.add(aadGroupId);
        }
        return groupId;
    }
}
