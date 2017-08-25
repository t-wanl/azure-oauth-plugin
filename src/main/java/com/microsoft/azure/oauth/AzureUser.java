package com.microsoft.azure.oauth;

import com.google.gson.annotations.SerializedName;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;

public class AzureUser implements UserDetails {

    public class AzureUserResponce {
        public AzureUser user;
    }

    @SerializedName("name")
    public String userName;
    @SerializedName("given_name")
    public String givenName;
    @SerializedName("family_name")
    public String familyName;
    @SerializedName("unique_name")
    public String uniqueName;
    @SerializedName("tid")
    public String tenantID;
    @SerializedName("oid")
    public String objectID;

    public AzureUser() {
        super();
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY };
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.uniqueName;
//        return
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getTenantID() {
        return tenantID;
    }

    public String getObjectID() {
        return objectID;
    }
}
