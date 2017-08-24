package com.microsoft.azure.oauth;

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
    public static Set<String> getGroupMembers(List<String> groupList, String accessToken, String tenant)
            throws IOException, JSONException {
        Map<String, String> groupNameId = getGroupNameId(groupList, accessToken, tenant);
        Set<String> members = new HashSet<String>();
        for (Map.Entry<String, String> group : groupNameId.entrySet()) {
            String name = group.getKey();
            String id = group.getValue();
            if (!groupList.contains(name)) continue;
            members.addAll(getGroupMembers(id, accessToken, tenant));
        }
        return members;
    }

    private static Set<String> getGroupMembers(String groupID, String accessToken, String tenant) throws IOException, JSONException {
        Set<String> members = new HashSet<String>();

        String url = String.format("https://graph.windows.net/%s/groups/%s/members?api-version=1.6", tenant, groupID);
        HttpResponse response = HttpHelper.sendGet(url, accessToken);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray memberArray = json.getJSONArray("value");
        for (int i = 0; i < memberArray.length(); i++) {
            JSONObject member =  memberArray.getJSONObject(i);
            if (member.getString("objectType").equals("Group")) {
                String subGroupID = member.getString("objectId");
                Set<String> subMembers = getGroupMembers(subGroupID, accessToken, tenant);
                members.addAll(subMembers);
            }
        }

        return members;
    }

    private static Map<String, String> getGroupNameId(List<String> groupList, String accessToken, String tenant)
            throws IOException, JSONException {
        String url = String.format("https://graph.windows.net/%s/groups?api-version=1.6", tenant);

        HttpResponse response = HttpHelper.sendGet(url, accessToken);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray groups = json.getJSONArray("value");
        Map<String, String> aadGroupList = new HashMap<String, String>();
        Map<String, String> groupNameId = new HashMap<String, String>();
        for (int i = 0; i < groups.length(); i++) {
            String aadGroupName = groups.getJSONObject(i).getString("displayName");
            String aadGroupId = groups.getJSONObject(i).getString("objectId");
            groupNameId.put(aadGroupName, aadGroupId);
        }
        return groupNameId;
    }


}
