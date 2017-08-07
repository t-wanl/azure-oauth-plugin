package com.microsoft.azure.oauth;

import com.microsoft.azure.oauth.api.AzureActiveDirectoryApiService;
import com.microsoft.azure.oauth.api.AzureActiveDirectoryConfig;
import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.Extension;
import hudson.Util;
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
import org.scribe.model.Token;
import org.springframework.dao.DataAccessException;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureActiveDirectorySecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureActiveDirectorySecurityRealm.class.getName() + ".referer";
    private static final String ACCESS_TOKEN_ATTRIBUTE = AzureActiveDirectorySecurityRealm.class.getName() + ".access_token";
    private static final Logger LOGGER = Logger.getLogger(AzureActiveDirectorySecurityRealm.class.getName());

//    private String clientID;
//    private String clientSecret;
    private AzureActiveDirectoryConfig config;

    @DataBoundConstructor
    public AzureActiveDirectorySecurityRealm(String pattern, String tenant, String clientID, String clientSecret) {
        super();
//        this.clientID = Util.fixEmptyAndTrim(clientID);
//        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
        this.config = new AzureActiveDirectoryConfig(Util.fixEmptyAndTrim(pattern), Util.fixEmptyAndTrim(tenant),
                Util.fixEmptyAndTrim(clientID), Util.fixEmptyAndTrim(clientSecret), null, null,
                null);
    }

    public AzureActiveDirectorySecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "AzureActiveDirectorySecurityRealm()");
    }

    /**
     * @return the clientID
     */
    public String getClientID() {
        return config.getClientID();
    }

    /**
     * @param clientID the clientID to set
     */
    public void setClientID(String clientID) {
        this.config.setClientID(clientID);
    }

    /**
     * @return the clientSecret
     */
    public String getClientSecret() {
        return config.getClientSecret();
    }

    /**
     * @param clientSecret the clientSecret to set
     */
    public void setClientSecret(String clientSecret) {
        config.setClientSecret(clientSecret);
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {

        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
        	throw new RuntimeException("Jenkins is not started yet.");
        }
		String rootUrl = jenkins.getRootUrl();
        if (StringUtils.endsWith(rootUrl, "/")) {
            rootUrl = StringUtils.left(rootUrl, StringUtils.length(rootUrl) - 1);
        }
        String callback = rootUrl + "/securityRealm/finishLogin";

        AzureActiveDirectoryApiService azureActiveDirectoryApiService = new AzureActiveDirectoryApiService(config);

        Token requestToken = azureActiveDirectoryApiService.createRquestToken();
        request.getSession().setAttribute(ACCESS_TOKEN_ATTRIBUTE, requestToken);

        return new HttpRedirect(azureActiveDirectoryApiService.createAuthorizationCodeURL(requestToken));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("oauth_verifier");

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }

        Token requestToken = (Token) request.getSession().getAttribute(ACCESS_TOKEN_ATTRIBUTE);

        Token accessToken = new AzureActiveDirectoryApiService(config).getTokenByAuthorizationCode(code, requestToken);

        if (!accessToken.isEmpty()) {

            AzureActiveDirectoryAuthenticationToken auth = new AzureActiveDirectoryAuthenticationToken(accessToken, clientID, clientSecret);
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
                if (authentication instanceof AzureActiveDirectoryAuthenticationToken) {
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

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails result = null;
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) {
            throw new UsernameNotFoundException("AzureActiveDirectoryAuthenticationToken = null, no known user: " + username);
        }
        if (!(token instanceof AzureActiveDirectoryAuthenticationToken)) {
          throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
        }
        result = new AzureActiveDirectoryApiService(config).getUserByUsername(username);
        if (result == null) {
            throw new UsernameNotFoundException("User does not exist for login: " + username);
        }
        return result;
    }

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
            return type == AzureActiveDirectorySecurityRealm.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            AzureActiveDirectorySecurityRealm realm = (AzureActiveDirectorySecurityRealm) source;

            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

            String node = reader.getNodeName();

            reader.moveDown();

            AzureActiveDirectorySecurityRealm realm = new AzureActiveDirectorySecurityRealm();

            node = reader.getNodeName();

            String value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

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

        private void setValue(AzureActiveDirectorySecurityRealm realm, String node, String value) {

            if (node.equalsIgnoreCase("clientid")) {
                realm.setClientID(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
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
