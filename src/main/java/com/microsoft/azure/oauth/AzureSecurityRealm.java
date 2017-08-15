package com.microsoft.azure.oauth;

//
//import com.microsoft.azure.oauth.api.AzureActiveDirectoryApiService;
//import com.microsoft.azure.oauth.api.AzureActiveDirectoryConfig;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.compute.KnownLinuxVirtualMachineImage;
import com.microsoft.azure.management.compute.VirtualMachine;
import com.microsoft.azure.management.compute.VirtualMachineSizeTypes;
import com.microsoft.azure.management.resources.fluentcore.arm.Region;
import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;


import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONObject;
import org.kohsuke.stapler.*;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.springframework.dao.DataAccessException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    private static final String ACCESS_TOKEN_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".access_token";
    private static final Token EMPTY_TOKEN = null;
    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());

    private String clientID;
    private String clientSecret;
    private String tenant;
    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    private OAuthService getService() {
        AzureApi api = new AzureApi();
        api.setTenant(this.getTenant());
        OAuthConfig config = new OAuthConfig(clientID, clientSecret, getCallback(), null, null, null);
        OAuthService service = new ServiceBuilder().provider(AzureApi.class)
                .apiKey(clientID).apiSecret(clientSecret).callback(getCallback())
                .build();

        return service;
    }

//    private AzureOAuth2Service service;

    private String getCallback() {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new RuntimeException("Jenkins is not started yet.");
        }
        String rootUrl = jenkins.getRootUrl();
        if (StringUtils.endsWith(rootUrl, "/")) {
            rootUrl = StringUtils.left(rootUrl, StringUtils.length(rootUrl) - 1);
        }
        String callback = rootUrl + "/securityRealm/finishLogin";
        return callback;
    }

    @DataBoundConstructor
    public AzureSecurityRealm(String tenant, String clientID, String clientSecret) {
        super();
        OAuthConfig config = new OAuthConfig(clientID, clientSecret, this.getCallback(), null, null, null);
        this.clientID = clientID;
        this.clientSecret = clientSecret;
        this.tenant = tenant;
    }



    public AzureSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "AzureSecurityRealm()");
    }



    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {

        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

//        Token requestToken = service.getRequestToken();
//        request.getSession().setAttribute(ACCESS_TOKEN_ATTRIBUTE, requestToken);
//
//        return new HttpRedirect(service.getAuthorizationUrl(requestToken));
        OAuthService service = getService();

        return new HttpRedirect(service.getAuthorizationUrl(EMPTY_TOKEN));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws Exception {
        String code = request.getParameter("code");

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }

//        Token requestToken = (Token) request.getSession().getAttribute(ACCESS_TOKEN_ATTRIBUTE);
        Verifier v = new Verifier(code);

        OAuthService service = getService();

        Token accessToken = null;
        accessToken = service.getAccessToken(EMPTY_TOKEN, v);


        if (!accessToken.isEmpty()) {
            AzureAuthenticationToken auth = null;
            if (accessToken instanceof AzureApiToken) {
                AzureApiToken azureApiToken = (AzureApiToken)accessToken;
                auth = new AzureAuthenticationToken(azureApiToken);
            }
            else
                return HttpResponses.redirectToContextRoot(); // TODO

            SecurityContextHolder.getContext().setAuthentication(auth);

            User u = User.current();
            if (u != null) {
                u.setFullName(auth.getName());
            }

        } else {
            LOGGER.log(Level.SEVERE, "doFinishLogin() accessToken = null");
        }

        test(tenant, accessToken);
        // redirect to referer
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    private void test(String tenant, Token accessToken) throws Exception {

        final String linuxVMName1 = "lwp_oauth_VM1";
        final String rgName = "lwp_oauth_rgCOMV";
        final String publicIPDnsLabel = "lwp_oauth_pip";
        final String userName = "albertxavier";
        final String password = "21521086";

        sendPost(tenant, accessToken);

    }

    // HTTP POST request
    private void sendPost(String tenant, Token accessToken) throws Exception {
        final String USER_AGENT = "Mozilla/5.0";
        //applications
        System.out.println("token = " + accessToken.getToken());
        String url = String.format("https://graph.windows.net/%s/applications?api-version=beta", tenant, accessToken.getToken());

        HttpClient client = new DefaultHttpClient();
        HttpPost post = new HttpPost(url);

        // add header
//        post.setHeader("User-Agent", USER_AGENT);
//        post.setHeader("User-Agent", USER_AGENT);
        post.setHeader("api-version", "beta");
        post.setHeader("Authorization", "Bearer " + accessToken.getToken());
        post.setHeader("Accept", "application/json, text/plain, */*");
        post.setHeader("Content-Type", "application/json;charset=UTF-8");

//        List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
//        urlParameters.add(new BasicNameValuePair("sn", "C02G8416DRJM"));
        JSONObject json = new JSONObject();
        JSONArray jsonArray = new JSONArray();
        jsonArray.put("https://localtest");
        json.put("displayName", "lwp oauth test create app");
        json.put("homePage", "http://homepage");
        json.put("identifierUris", jsonArray);
        post.setEntity(new StringEntity(json.toString()));

        org.apache.http.HttpResponse response = client.execute(post);
        System.out.println("\nSending 'POST' request to URL : " + url);
//        System.out.println("Post parameters : " + post.getEntity());
        System.out.println("Response Code : " +
                response.getStatusLine().getStatusCode());

        BufferedReader rd = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent()));

        StringBuffer result = new StringBuffer();
        String line = "";
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }

        System.out.println(result.toString());

    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof AzureApiToken) {
                    return authentication;
                }

                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username)  throws UserMayOrMayNotExistException, DataAccessException {
                throw new UserMayOrMayNotExistException("Cannot verify users in this context");
            }
        });
    }

//    @Override
//    public UserDetails loadUserByUsername(String username) {
//        UserDetails result = null;
//        Authentication token = SecurityContextHolder.getContext().getAuthentication();
//        if (token == null) {
//            throw new UsernameNotFoundException("AzureAuthenticationToken = null, no known user: " + username);
//        }
//        if (!(token instanceof AzureAuthenticationToken)) {
//          throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
//        }
//        result = service.getUserByUsername(username);
//        if (result == null) {
//            throw new UsernameNotFoundException("User does not exist for login: " + username);
//        }
//        return result;
//    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
        throw new UsernameNotFoundException("groups not supported");
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    public static final class ConverterImpl implements Converter {

        public boolean canConvert(Class type) {
            return type == AzureSecurityRealm.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            AzureSecurityRealm realm = (AzureSecurityRealm) source;

            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();

            writer.startNode("tenant");
            writer.setValue(realm.getTenant());
            writer.endNode();
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

            String node = reader.getNodeName();

            reader.moveDown();

            AzureSecurityRealm realm = new AzureSecurityRealm();

            node = reader.getNodeName();

            String value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

            //

            reader.moveDown();

            node = reader.getNodeName();

            value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

            //

            reader.moveDown();

            node = reader.getNodeName();

            value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();



            if (reader.hasMoreChildren()) {
                reader.moveDown();

                node = reader.getNodeName();

                value = reader.getValue();

                setValue(realm, node, value);

                reader.moveUp();
            }
            return realm;
        }

        private void setValue(AzureSecurityRealm realm, String node, String value) {

            if (node.equalsIgnoreCase("clientid")) {
                realm.setClientID(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
            } else if (node.equalsIgnoreCase("tenant")) {
                realm.setTenant(value);
            } else {
                throw new ConversionException("invalid node value = " + node);
            }

        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getHelpFile() {
            return "";
        }

        @Override
        public String getDisplayName() {
            return "Azure OAuth Plugin";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }
    }

}
