package com.microsoft.azure.oauth;

import hudson.BulkChange;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.GlobalSecurityConfiguration;
import hudson.util.FormApply;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by t-wanl on 8/31/2017.
 */

@Extension
public class MyGlobalSecurityConfiguration extends GlobalSecurityConfiguration {
    private static final Logger LOGGER = Logger.getLogger(GlobalSecurityConfiguration.class.getName());

    @Override
    public synchronized void doConfigure(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException, Descriptor.FormException {
        BulkChange bc = new BulkChange(Jenkins.getInstance());

        try {
            boolean result = this.configure(req, req.getSubmittedForm());
            LOGGER.log(Level.FINE, "security saved: " + result);
            Jenkins.getInstance().save();
            FormApply.success(req.getContextPath() + "/manage").generateResponse(req, rsp, (Object)null);
        } finally {
            bc.commit();
        }

    }
}
