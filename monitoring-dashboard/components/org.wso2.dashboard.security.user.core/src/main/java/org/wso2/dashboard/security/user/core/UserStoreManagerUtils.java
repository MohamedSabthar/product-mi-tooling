/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.dashboard.security.user.core;

import org.wso2.dashboard.security.user.core.common.DashboardUserStoreException;
import org.wso2.dashboard.security.user.core.common.DataHolder;
import org.wso2.dashboard.security.user.core.file.FileBasedUserStoreManager;
import org.wso2.dashboard.security.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.dashboard.security.user.core.ldap.ReadOnlyLDAPUserStoreManager;
import org.wso2.micro.integrator.security.MicroIntegratorSecurityUtils;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
import org.wso2.micro.integrator.security.user.api.UserStoreManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import static org.wso2.dashboard.security.user.core.UserStoreConstants.DEFAULT_JDBC_USERSTORE_MANAGER;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.DEFAULT_LDAP_USERSTORE_MANAGER;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.DOMAIN_SEPARATOR;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.SUPER_TENANT_ID;

public class UserStoreManagerUtils {

    public static UserStoreManager getUserStoreManager() throws UserStoreException, DashboardUserStoreException {
        DataHolder dataHolder = DataHolder.getInstance();
        if (dataHolder.getUserStoreManager() == null) {
            initializeUserStore();
        }
        return dataHolder.getUserStoreManager();
    }

    public static void initializeUserStore() throws UserStoreException, DashboardUserStoreException {
        DataHolder dataHolder = DataHolder.getInstance();
        if (isFileBasedUserStoreEnabled()) {
            dataHolder.setUserStoreManager(FileBasedUserStoreManager.getUserStoreManager());
            return;
        }
        RealmConfiguration config = RealmConfigXMLProcessor.createRealmConfig();
        if (config == null) {
            throw new UserStoreException("Unable to create Realm Configuration");
        }
        dataHolder.setRealmConfig(config);

        UserStoreManager userStoreManager;
        String userStoreMgtClassStr = config.getUserStoreClass();
        switch (userStoreMgtClassStr) {
            case DEFAULT_LDAP_USERSTORE_MANAGER: {
                userStoreManager = new ReadOnlyLDAPUserStoreManager(config, null, null);
                break;
            }
            case DEFAULT_JDBC_USERSTORE_MANAGER: {
                userStoreManager = new JDBCUserStoreManager(config, new Hashtable<>(), null, null,
                        SUPER_TENANT_ID);
                break;
            }
            default: {
                userStoreManager = (UserStoreManager) MicroIntegratorSecurityUtils.
                        createObjectWithOptions(userStoreMgtClassStr, config);
                break;
            }
        }
        dataHolder.setUserStoreManager(userStoreManager);
    }

    public static boolean isFileBasedUserStoreEnabled() {
        return Boolean.parseBoolean(System.getProperty("is.user.store.file.based"));
    }

    public static String addDomainToName(String name, String domainName) {
        if (!name.contains(DOMAIN_SEPARATOR) && !PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(domainName)) {
            // domain name is not already appended, and if exist in user-mgt.xml, append it.
            if (domainName != null) {
                // append domain name if exist
                domainName = domainName.toUpperCase() + DOMAIN_SEPARATOR;
                name = domainName + name;
            }
        }
        return name;
    }

    /**
     * Domain name is not already appended, and if it is provided or if exist in user-mgt.xml,
     * append it
     *
     * @param names
     * @param domainName
     * @return
     */
    public static String[] addDomainToNames(String[] names, String domainName) {
        if (domainName != null) {
            domainName = domainName.toUpperCase();
        }

        if (names == null || names.length == 0) {
            return names;
        }

        List<String> namesList = new ArrayList<>();
        for (String name : names) {
            if (domainName != null &&
                    !name.contains(DOMAIN_SEPARATOR) && !PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(domainName)) {
                name = UserStoreManagerUtils.addDomainToName(name, domainName);
            }
            namesList.add(name);
        }
        return namesList.toArray(new String[0]);
    }


    public static boolean isAdmin(String user) throws UserStoreException, DashboardUserStoreException {
        if (isFileBasedUserStoreEnabled()) {
            return FileBasedUserStoreManager.getUserStoreManager().isAdmin(user);
        }
        String[] roles = getUserStoreManager().getRoleListOfUser(user);
        return containsAdminRole(roles);
    }

    /**
     * Method to assert if the admin role is contained within a list of roles
     *
     * @param rolesList the list of roles assigned to a user
     * @return true if the admin role is present in the list of roles provided
     * @throws UserStoreException if any error occurs while reading the realm configuration
     */
    public static boolean containsAdminRole(String[] rolesList) {
        return Arrays.asList(rolesList).contains(DataHolder.getInstance().getRealmConfig().getAdminRoleName());
    }

    public static String getDomainName(RealmConfiguration realmConfig) {
        String domainName = realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME);
        return domainName != null ? domainName.toUpperCase() : null;
    }
}
