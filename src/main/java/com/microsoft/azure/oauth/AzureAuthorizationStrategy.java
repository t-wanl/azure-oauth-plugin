package com.microsoft.azure.oauth;

import com.google.common.collect.ImmutableList;
import com.microsoft.azure.management.Azure;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.util.Collection;

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
    }
}
