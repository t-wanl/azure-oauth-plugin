package com.microsoft.azure.oauth;


import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;

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
    private static final Cache<String, Set<String>> groupsByUPN =
            CacheBuilder.newBuilder().expireAfterAccess(1, CACHE_EXPIRY).build();

    public static Set<String> getGroupsByUPN(String upn) throws ExecutionException {
        return groupsByUPN.get(upn, new Callable<Set<String>>() {
            @Override
            public Set<String> call() throws Exception {
                Utils.TimeUtil.setBeginDate();

                Authentication auth = Jenkins.getAuthentication();
                if (!(auth instanceof AzureAuthenticationToken)) return null;
                String aadAccessToken = ((AzureAuthenticationToken) auth).getAzureAdToken().getToken();
                AzureResponse res = AzureAdApi.getGroupsByUserId(aadAccessToken);
                if (!res.isSuccess()) return null;
                Utils.TimeUtil.setEndDate();
                System.out.println("getGroupsByUPN time = " + Utils.TimeUtil.getTimeDifference() + "ms");
                return res.toSet();
            }
        });
    }

    public static void invalidate(String userId) {
            groupsByUPN.invalidate(userId);
    }
}
