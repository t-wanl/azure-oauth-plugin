package com.microsoft.azure.oauth;

import java.util.Date;

/**
 * Created by t-wanl on 8/23/2017.
 */
public class Utils {

    public static class TimeUtil {
        private static Date beginDate;
        private static Date endDate;

        public static void setBeginDate() {
//            TimeUtil.beginDate = beginDate;
            TimeUtil.beginDate = new Date();
        }

        public static void setEndDate() {
//            TimeUtil.endDate = endDate;
            TimeUtil.endDate = new Date();
        }

        public static Date getBeginDate() {
            return beginDate;
        }

        public static Date getEndDate() {
            return endDate;
        }

        public static long getTimeDifference() {
            long diff = endDate.getTime() - beginDate.getTime();
            beginDate = null;
            endDate = null;
            return diff;
        }
    }
    }

