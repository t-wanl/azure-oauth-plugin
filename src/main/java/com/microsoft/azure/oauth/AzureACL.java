package com.microsoft.azure.oauth;

import hudson.model.AbstractItem;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.security.Permission;
import org.acegisecurity.Authentication;
import org.json.JSONException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutionException;
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
    private final boolean allowAnonymousReadPermission;
    private final boolean allowAnonymousJobStatusPermission;
    private final AbstractItem item;

    public AzureACL(String adminUserNames,
                    String groupNames,
                    boolean authenticatedUserReadPermission,
                    boolean authenticatedUserCreateJobPermission,
                    boolean allowAnonymousReadPermission,
                    boolean allowAnonymousJobStatusPermission) {
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
        this.allowAnonymousReadPermission = allowAnonymousReadPermission;
        this.allowAnonymousJobStatusPermission = allowAnonymousJobStatusPermission;
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


            // for group user
            if (!groupNameList.isEmpty()) {

                try {
                    Set<String> groupsIncludeUser = ((AzureAuthenticationToken) a).getMemberGroups();
                    Set<String> intersection = new HashSet<String>(groupNameList);
                    intersection.retainAll(groupsIncludeUser);
                    if (!intersection.isEmpty() && checkAadGroupPermission(permission)) {
                        log.finest("Granting Authenticated User read permission to group "
                                + intersection.iterator().next());
                        System.out.println("user is in the group list");
                        System.out.println("grant permission  = " + permission);
                        return true;
                    }

                } catch (ExecutionException e) {
                    e.printStackTrace();
                }

//                try {
//                    String token = ((AzureAuthenticationToken) a).getAzureApiToken().getToken();
//                    String tenant = ((AzureAuthenticationToken) a).getAzureUser().getTenantID();
//                    Set<String> allGroupsID = null;
//
//                    allGroupsID = AzureAdApi.getAllAadGroupsId(token, tenant);
//                    Set<String> intersection = new HashSet<String>(groupNameList);
//                    intersection.retainAll(allGroupsID);
//                    if (!intersection.isEmpty() && isInGroup(a) && checkAadGroupPermission(permission)) {
//                        log.finest("Granting Authenticated User read permission to group "
//                                + intersection.iterator().next());
//                        System.out.println("grant permission = " + permission);
//                        return true;
//                    }
//                } catch (IOException e) {
//                    e.printStackTrace();
//                } catch (JSONException e) {
//                    e.printStackTrace();
//                }

            }

            // candidate id non-admin user, grant read rights
            if (authenticatedUserReadPermission && checkReadPermission(permission)) {
                log.finest("Granting Authenticated User read permission to user "
                        + candidateName);
                return true;
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
                if(checkJobStatusPermission(permission) && allowAnonymousJobStatusPermission) {
                    return true;
                }
                if (checkReadPermission(permission) && allowAnonymousReadPermission) {
                    log.finer("Granting Read rights to anonymous user.");
                    return true;
                }
                return false;
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

    private boolean checkAadGroupPermission(Permission permission) {
        System.out.println("check permission = " + permission);

        if (permission.getId().equals("hudson.model.Hudson.Read")
                || permission.getId().equals("hudson.model.Item.Workspace")
                || permission.getId().equals("hudson.model.Item.Read")
                || permission.getId().equals("hudson.model.Item.Create")) {
            return true;
        }

        if (permission.equals(Item.CREATE) ||
                permission.equals(Item.READ) ||
                permission.equals(Item.CONFIGURE) ||
                permission.equals(Item.BUILD) ||
                permission.equals(Item.DELETE) ||
                permission.equals(Item.EXTENDED_READ) ||
                permission.equals(Item.CANCEL)) {
            return true;
        }
        return false;
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

    private boolean checkJobStatusPermission(Permission permission) {
        return permission.getId().equals("hudson.model.Item.ViewStatus");
    }

    public boolean isInGroup(Authentication a) throws IOException, JSONException {
        if (a instanceof AzureAuthenticationToken) {
            String oid = ((AzureAuthenticationToken) a).getAzureUser().getObjectID();
            String accessToken = ((AzureAuthenticationToken) a).getAzureApiToken().getToken();
            String tenent = ((AzureAuthenticationToken) a).getAzureUser().getTenantID();

            Queue<String> queue = new LinkedList<String>();
            Set<String> visited = new HashSet<String>();

            for (String groupID : groupNameList) {
                queue.offer(groupID);
            }

            while (!queue.isEmpty()) {
                String curGroup = queue.poll();
                Map<String, String> members = AzureAdApi.getGroupMembers(curGroup, accessToken, tenent, false);
                for (Map.Entry<String, String> member : members.entrySet()) {
                    System.out.println("user: " + oid + "; member : " + member.getKey() + "; group: " + curGroup);
                    if (member.getKey().equals(oid)) return true;
                    if (member.getValue().equals("Group") && !visited.contains(member.getKey())) queue.offer(member.getKey());
                    visited.add(curGroup);
                }
            }

            return false;
        }

        return false;
    }

    public boolean isAuthenticatedUserReadPermission() {
        return authenticatedUserReadPermission;
    }

    public boolean isAuthenticatedUserCreateJobPermission() {
        return authenticatedUserCreateJobPermission;
    }

    public boolean isAllowAnonymousReadPermission() {
        return allowAnonymousReadPermission;
    }

    public boolean isAllowAnonymousJobStatusPermission() {
        return allowAnonymousJobStatusPermission;
    }

}
