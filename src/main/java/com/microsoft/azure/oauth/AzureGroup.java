package com.microsoft.azure.oauth;

import com.google.gson.annotations.SerializedName;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

public class AzureGroup extends AzureObject {

    @SerializedName("id")
    public String objectId;
    @SerializedName("displayName")
    public String displayName;
    @SerializedName("description")
    public String description;


    public AzureGroup() {
        super();
    }

    public String getDescription() {
        return description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getObjectId() {
        return objectId;
    }
}


