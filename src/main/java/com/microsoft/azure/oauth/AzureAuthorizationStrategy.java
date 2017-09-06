package com.microsoft.azure.oauth;

import com.google.common.collect.ImmutableList;
import com.microsoft.azure.management.Azure;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.util.FormValidation;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;
import org.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.scribe.utils.OAuthEncoder;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

/**
 * Created by t-wanl on 8/23/2017.
 */
public class AzureAuthorizationStrategy extends AuthorizationStrategy {

    private final AzureACL rootACL;

    @DataBoundConstructor
    public AzureAuthorizationStrategy(
            String adminUserNames,
            String groupNames,
            boolean authenticatedUserReadPermission,
            boolean authenticatedUserCreateJobPermission,
            boolean allowAnonymousReadPermission,
            boolean allowAnonymousJobStatusPermission) {
        super();
        rootACL = new AzureACL(adminUserNames, groupNames,
                authenticatedUserReadPermission, authenticatedUserCreateJobPermission,
                allowAnonymousReadPermission, allowAnonymousJobStatusPermission);
    }

    @Nonnull
    @Override
    public ACL getRootACL () {
        return rootACL;
    }

    @Nonnull
    @Override
    public Collection<String> getGroups() {
        return ImmutableList.of();
    }

    @Override
    public int hashCode() {
        return rootACL != null ? rootACL.hashCode() : 0;
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof AzureAuthorizationStrategy) {
            AzureAuthorizationStrategy obj = (AzureAuthorizationStrategy) object;
            return this.getGroupNames().equals(obj.getGroupNames()) &&
                    this.getAdminUserNames().equals(obj.getAdminUserNames()) &&
                    this.isAuthenticatedUserReadPermission() == obj.isAuthenticatedUserReadPermission() &&
                    this.isAuthenticatedUserCreateJobPermission() == obj.isAuthenticatedUserCreateJobPermission() &&
                    this.isAllowAnonymousReadPermission() == obj.isAllowAnonymousReadPermission() &&
                    this.isAllowAnonymousJobStatusPermission() == obj.isAllowAnonymousJobStatusPermission();
        }
        return false;
    }

    public String getGroupNames() {
        return StringUtils.join(rootACL.getGroupNameList().iterator(), ", ");
    }

    public String getAdminUserNames() {
        return StringUtils.join(rootACL.getAdminUserNameList().iterator(), ", ");
    }

    public boolean isAuthenticatedUserReadPermission() {
        return rootACL.isAuthenticatedUserReadPermission();
    }
    public boolean isAuthenticatedUserCreateJobPermission() {
        return rootACL.isAuthenticatedUserCreateJobPermission();
    }
    public boolean isAllowAnonymousReadPermission() {
        return rootACL.isAllowAnonymousReadPermission();
    }
    public boolean isAllowAnonymousJobStatusPermission() {
        return rootACL.isAllowAnonymousJobStatusPermission();
    }


    @Extension
    public static final class DescriptorImpl extends Descriptor<AuthorizationStrategy> {
        @Override
        public String getDisplayName() {
            return "Azure AD Authorization Strategy";
        }

        @Override
        public String getHelpFile() {
            return "";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends AuthorizationStrategy> clazz) {
            super(clazz);
        }

        public FormValidation doVerifyConfiguration(
                @QueryParameter final String adminUserNames,
                @QueryParameter final String groupNames,
                @QueryParameter final String clientsecret,
                @QueryParameter final String clientid,
                @QueryParameter final String tenant) throws IOException, JSONException, ExecutionException {



            org.apache.http.HttpResponse response = AzureAdApi.getAppOnlyAccessTokenResponce(clientid, clientsecret, tenant);
            int statusCode = HttpHelper.getStatusCode(response);
            String content = HttpHelper.getContent(response);
            if (statusCode != 200) {
//                JSONObject errJson = new JSONObject(content);
                return FormValidation.error(content);
            }

//            String content = AzureAuthenticationToken.getAppOnlyToken().get(AzureAuthenticationToken.APP_ONLY_TOKEN_KEY, new Callable<String>() {
//                @Override
//                public String call() throws Exception {
//                    org.apache.http.HttpResponse response = AzureAdApi.getAppOnlyAccessTokenResponce(clientid, clientsecret, tenant);
//                    int statusCode = HttpHelper.getStatusCode(response);
//                    String content = HttpHelper.getContent(response);
//                    if (statusCode != 200) return null;
//                    return content;
//                }
//            });

            if (content == null) {
                JSONObject errJson = new JSONObject(content);
                return FormValidation.error(content);
            }

            JSONObject json = new JSONObject(content);
            String accessToken = json.getString("access_token");
            System.out.println("Get app only token = \n" + accessToken);

            List<String> adminUserNameList = new LinkedList<String>();
            String[] admins = adminUserNames.split(",");

            for (String admin : admins) {
                admin = admin.trim();
                response = AzureAdApi.getUserResponse(tenant, admin, accessToken);
                statusCode = HttpHelper.getStatusCode(response);
                content = HttpHelper.getContent(response);
                if (statusCode != 200) {
                    JSONObject errJson = new JSONObject(content);
                    return FormValidation.error(content);
                }
            }

            List<String> groupList = new LinkedList<String>();
            String[] groups = groupNames.split(",");
            for (String group : groups) {
                group = group.trim();
                response = AzureAdApi.getGroupResponse(tenant, group, accessToken);
                statusCode = HttpHelper.getStatusCode(response);
                content = HttpHelper.getContent(response);
                if (statusCode != 200) {
                    JSONObject errJson = new JSONObject(content);
                    return FormValidation.error(content);
                }
            }

            return FormValidation.ok("Successfully verified");
        }
    }
}
