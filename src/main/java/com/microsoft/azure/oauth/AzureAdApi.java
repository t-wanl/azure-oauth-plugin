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
    public static Set<AbstractMap.SimpleEntry<String, String>> getGroupMembers(List<String> groupList, String accessToken, String tenant)
            throws IOException, JSONException {
        Map<String, String> groupNameId = getAllAadGroupsNameIdPair(accessToken, tenant);
        Set<AbstractMap.SimpleEntry<String, String>> members = new HashSet<AbstractMap.SimpleEntry<String, String>>();
        for (Map.Entry<String, String> group : groupNameId.entrySet()) {
            String name = group.getKey();
            String id = group.getValue();
            if (!groupList.contains(name)) continue;
            members.addAll(getGroupMembers(id, accessToken, tenant, true));
        }
        return members;
    }

    public static Set<AbstractMap.SimpleEntry<String, String>> getGroupMembers(String groupID, String accessToken, String tenant, boolean recursive) throws IOException, JSONException {
        Set<AbstractMap.SimpleEntry<String, String>> members = new HashSet<AbstractMap.SimpleEntry<String, String>>();

        String url = String.format("https://graph.windows.net/%s/groups/%s/members?api-version=1.6", tenant, groupID);
        HttpResponse response = HttpHelper.sendGet(url, accessToken);
        String responseContent = HttpHelper.getContent(response);

        JSONObject json = new JSONObject(responseContent);
        JSONArray memberArray = json.getJSONArray("value");
        for (int i = 0; i < memberArray.length(); i++) {
            JSONObject member =  memberArray.getJSONObject(i);
            if (recursive && member.getString("objectType").equals("Group")) {
                String subGroupID = member.getString("objectId");
                Set<AbstractMap.SimpleEntry<String, String>> subMembers = getGroupMembers(subGroupID, accessToken, tenant, recursive);
                members.addAll(subMembers);
            } else if (member.getString("objectType").equals("User")) {
                String userID = member.getString("objectId");
                members.add(new AbstractMap.SimpleEntry<String, String>(userID, "User"));
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
}
