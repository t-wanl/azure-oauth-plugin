package com.microsoft.azure.oauth;

import com.google.gson.Gson;
import hudson.model.AutoCompletionCandidates;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.apache.commons.collections4.ListUtils;
import org.json.JSONException;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

/**
 * Created by t-wanl on 8/23/2017.
 */
public class Utils {

    public static class TimeUtil {
        private static Date beginDate;
        private static Date endDate;

        public static void setBeginDate() {
//            TimeUtil.beginDate = beginDate;
            TimeUtil.beginDate = new Date();
        }

        public static void setEndDate() {
//            TimeUtil.endDate = endDate;
            TimeUtil.endDate = new Date();
        }

        public static Date getBeginDate() {
            return beginDate;
        }

        public static Date getEndDate() {
            return endDate;
        }

        public static long getTimeDifference() {
            if (beginDate == null || endDate == null) return -1;
            long diff = endDate.getTime() - beginDate.getTime();
            beginDate = null;
            endDate = null;
            return diff;
        }
    }

    public static class UUIDUtil {
        private static final Pattern pattern = Pattern
                .compile("(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-5][0-9a-f]{3}-?[089ab][0-9a-f]{3}-?[0-9a-f]{12}$");

        public static final boolean isValidUuid(final String uuid) {
            return ((uuid != null) && (uuid.trim().length() > 31)) ? pattern.matcher(uuid).matches() : false;
        }
    }

    public static class JenkinsUtil {
        public static SecurityRealm getSecurityRealm() {
            Jenkins jenkins = Jenkins.getInstance();
            if (jenkins == null) {
                throw new RuntimeException("Jenkins is not started yet.");
            }
            SecurityRealm realm = jenkins.getSecurityRealm();
            return realm;
        }

        public static AutoCompletionCandidates generateAutoCompletionForAadObjects(String value) throws JSONException, ExecutionException, IOException {
            AutoCompletionCandidates c = new AutoCompletionCandidates();

            SecurityRealm realm = Utils.JenkinsUtil.getSecurityRealm();
            if (!(realm instanceof AzureSecurityRealm)) return null;
            AzureApiToken appOnlyToken = AzureAuthenticationToken.getAppOnlyToken();
            Set<AzureObject> candidates = new HashSet<>();
            System.out.println("get all users");
            Set<AzureObject> users = AzureCachePool.getAllAzureObjects(AzureObjectType.User);
            if (users != null && !users.isEmpty()) candidates.addAll(users);
            System.out.println("get all groups");
            Set<AzureObject>  groups = AzureCachePool.getAllAzureObjects(AzureObjectType.Group);
            if (groups != null && !groups.isEmpty()) candidates.addAll(groups);

            for (AzureObject obj : candidates) {
                String candadateText = MessageFormat.format("{0} ({1})",obj.getDisplayName(), obj.getObjectId());
                if (ListUtils.longestCommonSubsequence(candadateText.toLowerCase(), value.toLowerCase()).equalsIgnoreCase(value))
                    c.add(candadateText);
            }

            return c;
        }
    }

    public static class GsonUtil {
        public static Object generateFromJsonString(String jsonStr, Class modelClass) {
            Gson gson = new Gson();
            Object obj = gson.fromJson(jsonStr, modelClass);
            return obj;
        }
    }



}

