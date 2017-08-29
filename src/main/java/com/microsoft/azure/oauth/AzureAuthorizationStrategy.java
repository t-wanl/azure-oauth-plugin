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
        public String getDisplayName() {
            return "Azure AD Authorization Strategy";
        }

        public FormValidation doVerifyConfiguration(@QueryParameter String adminUserNames,
                                                    @QueryParameter String groupNames,
                                                    @QueryParameter String tenant) throws IOException, JSONException {

            // try to get app-only token
            String url = String.format("https://login.microsoftonline.com/%s/oauth2/token", tenant);

            List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
            urlParameters.add(new BasicNameValuePair("client_id", "f8e021e7-cecb-402e-a503-ce022c16bc64"));
            urlParameters.add(new BasicNameValuePair("scope", OAuthEncoder.encode("https://graph.windows.net")));
            urlParameters.add(new BasicNameValuePair("client_secret", "vi0eulNg8U9Q3jrqc4qpEHK65MqaP6v47xAJfr8ynMc="));
            urlParameters.add(new BasicNameValuePair("grant_type", "client_credentials"));
            HttpEntity formEntity=new UrlEncodedFormEntity(urlParameters,ContentType.APPLICATION_FORM_URLENCODED.getCharset());

            org.apache.http.HttpResponse response = HttpHelper.sendPost(url, null, formEntity, ContentType.APPLICATION_FORM_URLENCODED);
            int statusCode = HttpHelper.getStatusCode(response);
            String content = HttpHelper.getContent(response);
            JSONObject json = new JSONObject(content);
            String accessToken = json.getString("access_token");

            List<String> adminUserNameList = new LinkedList<String>();
            String[] admins = adminUserNames.split(",");

            for (String admin : admins) {
                url = String.format("https://graph.windows.net/%s/users/%s", tenant, OAuthEncoder.encode(admin));
                response = HttpHelper.sendGet(url, accessToken);
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
                url = String.format("https://graph.windows.net/%s/groups/%s", tenant, OAuthEncoder.encode(group));
                response = HttpHelper.sendGet(url, accessToken);
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
