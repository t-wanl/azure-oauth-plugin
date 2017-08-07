package com.microsoft.azure.oauth;

import com.microsoft.azure.oauth.api.AzureActiveDirectoryApiService;
import hudson.Extension;
import hudson.model.Descriptor;
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
import org.springframework.dao.DataAccessException;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by t-wanl on 8/4/2017.
 */
public class AzureActiveDirectorySecurityRealm extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(AzureActiveDirectorySecurityRealm.class.getName());

    @DataBoundConstructor
    AzureActiveDirectorySecurityRealm() {
        super();
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
        throw new UsernameNotFoundException("groups not supported");
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails result = null;
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) {
            throw new UsernameNotFoundException("AzureActiveDirectoryAuthenticationToken = null, no known user: " + username);
        }
        if (!(token instanceof AzureAuthenticationToken)) {
            throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
        }
        result = new AzureActiveDirectoryApiService(clientID, clientSecret).getUserByUsername(username);
        if (result == null) {
            throw new UsernameNotFoundException("User does not exist for login: " + username);
        }
        return result;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityRealm.SecurityComponents(new AuthenticationManager() {
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

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new RuntimeException("Jenkins is not started yet.");
        }

        String rootUrl = jenkins.getRootUrl();
        if (StringUtils.endsWith(rootUrl, "/")) {
            rootUrl = StringUtils.left(rootUrl, StringUtils.length(rootUrl) - 1);
        }
        String callback = rootUrl + "/securityRealm/finishLogin";
        AzureActiveDirectoryApiService azureActiveDirectoryApiService = new AzureActiveDirectoryApiService(); // TODO

        return HttpRedirect(); // TODO
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("oauth_verifier");
        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }
        // TODO
        return
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
