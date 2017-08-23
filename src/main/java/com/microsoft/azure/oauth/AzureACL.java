package com.microsoft.azure.oauth;

import hudson.model.AbstractItem;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.security.Permission;
import org.acegisecurity.Authentication;

import javax.annotation.Nonnull;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Created by t-wanl on 8/23/2017.
 */
public class AzureACL extends ACL{
    private static final Logger log = Logger
            .getLogger(AzureACL.class.getName());

    private final List<String> adminUserNameList;
    private final List<String> groupNameList;
    private final boolean authenticatedUserReadPermission;
    private final boolean authenticatedUserCreateJobPermission;
    private final AbstractItem item;

    public AzureACL(String adminUserNames,
                    String groupNames,
                    boolean authenticatedUserReadPermission,
                    boolean authenticatedUserCreateJobPermission) {
        super();

        this.adminUserNameList = new LinkedList<String>();
        String[] parts = adminUserNames.split(",");
        for (String part : parts) {
            adminUserNameList.add(part.trim());
        }

        this.groupNameList = new LinkedList<String>();
        parts = groupNames.split(",");
        for (String part : parts) {
            groupNameList.add(part.trim());
        }

        this.authenticatedUserReadPermission = authenticatedUserReadPermission;
        this.authenticatedUserCreateJobPermission = authenticatedUserCreateJobPermission;

        this.item = null;
    }

    @Override
    public boolean hasPermission(@Nonnull Authentication a, @Nonnull Permission permission) {
        if (a instanceof AzureAuthenticationToken) {
            if (!a.isAuthenticated()) {
                return false;
            }

            AzureAuthenticationToken authenticationToken = (AzureAuthenticationToken) a;

            String candidateName = a.getName();

            // candidate is an admin user, grant admin rights
            if (adminUserNameList.contains(candidateName)) {
                log.finest("Granting Admin rights to user " + candidateName);
                return true;
            }

            if (this.item != null) {
                if (authenticatedUserReadPermission) {
                    if (checkReadPermission(permission)) {
                        log.finest("Granting Authenticated User read permission " +
                                "on project " + item.getName() +
                                "to user " + candidateName);
                        return true;
                    }
                }


            } else {
                // candidate id non-admin user, grant read rights
                if (authenticatedUserReadPermission && checkReadPermission(permission)) {
                    log.finest("Granting Authenticated User read permission to user "
                            + candidateName);
                    return true;
                }
            }

            if (authenticatedUserCreateJobPermission && permission.equals(Item.CREATE)) {
                return true;
            }

        } else {
            String authenticatedUserName = a.getName();
            if (authenticatedUserName == null) {
                throw new IllegalArgumentException("Authentication must have a valid name");
            }

            if (authenticatedUserName.equals(SYSTEM.getPrincipal())) {
                // give system user full access
                log.finest("Granting Full rights to SYSTEM user.");
                return true;
            }

            if (authenticatedUserName.equals("anonymous")) {
                // TODO


            }
        }

        return false;
    }

    public List<String> getAdminUserNameList() {
        return adminUserNameList;
    }

    public List<String> getGroupNameList() {
        return groupNameList;
    }

    private boolean checkReadPermission(Permission permission) {
        if (permission.getId().equals("hudson.model.Hudson.Read")
                || permission.getId().equals("hudson.model.Item.Workspace")
                || permission.getId().equals("hudson.model.Item.Read")) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isAuthenticatedUserReadPermission() {
        return authenticatedUserReadPermission;
    }

    public boolean isAuthenticatedUserCreateJobPermission() {
        return authenticatedUserCreateJobPermission;
    }

}
