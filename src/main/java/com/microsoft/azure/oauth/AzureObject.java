package com.microsoft.azure.oauth;

import com.google.gson.annotations.SerializedName;

public abstract class AzureObject {
    public abstract String getObjectId();
    public abstract String getDisplayName();
}


