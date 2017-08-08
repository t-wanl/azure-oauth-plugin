package com.microsoft.azure.oauth;


//
//import com.microsoft.azure.oauth.api.AzureActiveDirectoryApiService;
//import com.microsoft.azure.oauth.api.AzureActiveDirectoryConfig;
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
import org.kohsuke.stapler.*;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.springframework.dao.DataAccessException;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    private static final String ACCESS_TOKEN_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".access_token";

    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());

//    private OAuthConfig config;

    private String clientID;
    private String clientSecret;
    private String tenant;
    private AzureOAuth2Api api;
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

    private AzureOAuth2Service service;

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

        this.service = new AzureOAuth2Service(api, config);
    }



    public AzureSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "AzureSecurityRealm()");
    }



    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {

        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        Token requestToken = service.getRequestToken();
        request.getSession().setAttribute(ACCESS_TOKEN_ATTRIBUTE, requestToken);

        return new HttpRedirect(service.getAuthorizationUrl(requestToken));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("oauth_verifier");

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }

        Token requestToken = (Token) request.getSession().getAttribute(ACCESS_TOKEN_ATTRIBUTE);
        Verifier v = new Verifier(code);
        Token accessToken = service.getAccessToken(requestToken, v);

        if (!accessToken.isEmpty()) {

            AzureAuthenticationToken auth =
                    new AzureAuthenticationToken(accessToken, service);
            SecurityContextHolder.getContext().setAuthentication(auth);

            User u = User.current();
            if (u != null) {
                u.setFullName(auth.getName());
            }

        } else {
            LOGGER.log(Level.SEVERE, "doFinishLogin() accessToken = null");
        }

        // redirect to referer
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof AzureAuthenticationToken) {
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
