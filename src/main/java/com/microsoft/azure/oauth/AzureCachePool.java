package com.microsoft.azure.oauth;


import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.json.JSONException;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Created by albertxavier on 2017/9/7.
 */
public class AzureCachePool {
    public static final TimeUnit CACHE_EXPIRY = TimeUnit.HOURS;
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static final Cache<String, Set<String>> belongingGroupsByUPN =
            CacheBuilder.newBuilder().expireAfterAccess(1, CACHE_EXPIRY).build();
    private static final Cache<String, Set<AzureIdTokenUser>> usersByUPN =
            CacheBuilder.newBuilder().expireAfterAccess(1, CACHE_EXPIRY).build();
    private static final Cache<String, Set<AzureGroup>> groupsByUPN =
            CacheBuilder.newBuilder().expireAfterAccess(1, CACHE_EXPIRY).build();

    public static Set<String> getBelongingGroupsByUPN(String upn) throws ExecutionException, IOException, JSONException {

        if (Constants.DEBUG == true) {
            Utils.TimeUtil.setBeginDate();

            Authentication auth = Jenkins.getAuthentication();
            if (!(auth instanceof AzureAuthenticationToken)) return new HashSet<String>();
            String aadAccessToken = ((AzureAuthenticationToken) auth).getAzureAdToken().getToken();
            AzureResponse res = AzureAdApi.getGroupsByUserId(aadAccessToken);
            if (!res.isSuccess()) {
                System.out.println("getBelongingGroupsByUPN: set is empty");
                System.out.println("error: " + res.getResponseContent());
                return new HashSet<String>();
            }
            Utils.TimeUtil.setEndDate();
            System.out.println("getBelongingGroupsByUPN time (debug) = " + Utils.TimeUtil.getTimeDifference() + "ms");
            System.out.println("getBelongingGroupsByUPN: set = " + res.toSet());
            return res.toSet();
        }

        return belongingGroupsByUPN.get(upn, new Callable<Set<String>>() {
            @Override
            public Set<String> call() throws Exception {
                Utils.TimeUtil.setBeginDate();

                Authentication auth = Jenkins.getAuthentication();
                if (!(auth instanceof AzureAuthenticationToken)) return new HashSet<String>();
                String aadAccessToken = ((AzureAuthenticationToken) auth).getAzureAdToken().getToken();
                AzureResponse res = AzureAdApi.getGroupsByUserId(aadAccessToken);
                if (!res.isSuccess()) return new HashSet<String>();
                Utils.TimeUtil.setEndDate();
                System.out.println("getBelongingGroupsByUPN time = " + Utils.TimeUtil.getTimeDifference() + "ms");
                return res.toSet();
            }
        });
    }

    public static void invalidate(String userId) {
            belongingGroupsByUPN.invalidate(userId);
    }
}
