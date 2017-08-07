package com.microsoft.azure.oauth.api;

/**
 * Created by t-wanl on 8/7/2017.
 */
public class AzureActiveDirectoryConfig {

    private String clientID; //在第三方平台注册后生成的消费平台应用id

    private String clientSecret;//在第三方平台注册后生成的消费平台应用secret

    private String callback;//第三方平台在用户登录及授权操作通过后，消费平台的回调地址。

    private String scope;//申请的权限范围，可选

    private Class apiClass;//记载获取第三方校验信息api地址的类，大平台的api类多在scribe中有封装

//    private String oAuthEndpointPattern = "https://login.microsoftonline.com/%s/oauth2/";
    private String oAuthEndpointPattern;

//    private String tenant= "72f988bf-86f1-41af-91ab-2d7cd011db47";
    private String tenant;

    public AzureActiveDirectoryConfig(String oAuthEndpointPattern, String tenant, String clientID, String clientSecret, String callback, String scope,
                              Class apiClass) {
        super();
        this.oAuthEndpointPattern = oAuthEndpointPattern;
        this.tenant = tenant;
        this.clientID = clientID;
        this.clientSecret = clientSecret;
        this.callback = callback;
        this.apiClass = apiClass;
        this.scope = scope;
    }

    public String getClientID() {
        return this.clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getClientSecret() {
        return this.clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getCallback() {
        return this.callback;
    }

    public String getScope() {
        return this.scope;
    }

    public boolean hasScope() {
        return this.scope != null;
    }

    public String getTenant() {
        return tenant;
    }

    public String getoAuthEndpointPattern() {
        return oAuthEndpointPattern;
    }

    public String getoAuthEndpointWithTenant() {
        return String.format(this.oAuthEndpointPattern, this.tenant);
    }
}
