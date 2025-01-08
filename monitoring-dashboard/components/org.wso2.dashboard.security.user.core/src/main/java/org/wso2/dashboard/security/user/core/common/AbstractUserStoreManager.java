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

package org.wso2.dashboard.security.user.core.common;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dashboard.security.user.core.UserStoreManagerUtils;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserRealm;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.hybrid.HybridRoleManager;
import org.wso2.micro.integrator.security.user.core.system.SystemUserRoleManager;

import javax.sql.DataSource;
import java.nio.CharBuffer;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.dashboard.security.user.core.UserStoreConstants.DOMAIN_SEPARATOR;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.REGISTRY_SYSTEM_USERNAME;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.LEADING_OR_TRAILING_SPACE_ALLOWED_IN_USERNAME;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.SHARED_GROUPS_ENABLED;
import static org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION;
import static org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION;
import static org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE;

public abstract class AbstractUserStoreManager implements UserStoreManager {
    private static final Log log = LogFactory.getLog(AbstractUserStoreManager.class);
    protected static final String TRUE_VALUE = "true";
    protected int tenantId;
    protected DataSource dataSource = null;
    protected RealmConfiguration realmConfig = null;
    protected ClaimManager claimManager = null;
    protected UserRealm userRealm = null;
    protected HybridRoleManager hybridRoleManager = null;
    protected SystemUserRoleManager systemUserRoleManager = null;
    protected boolean readGroupsEnabled = false;
    protected boolean writeGroupsEnabled = false;

    @Override
    public boolean authenticate(final String userName, final Object credential) {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                validateUserNameAndCredential(userName, credential);
                boolean domainProvided = userName.contains(DOMAIN_SEPARATOR);
                return authenticate(userName, credential, domainProvided);
            });
        } catch (PrivilegedActionException e) {
            throw new RuntimeException("Error during authentication", e);
        }
    }

    protected boolean authenticate(final String userName, final Object credential, final boolean domainProvided)
            throws PrivilegedActionException {
        return AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) ()
                -> authenticateInternal(userName, credential, domainProvided));
    }

    private boolean authenticateInternal(String userName, Object credential, boolean domainProvided)
            throws UserStoreException, DashboardUserStoreException, PrivilegedActionException {
        AbstractUserStoreManager abstractUserStoreManager = this;
        UserStore userStore = abstractUserStoreManager.getUserStore(userName);
        if (userStore.isRecursive() && userStore.getUserStoreManager() instanceof AbstractUserStoreManager) {
            return ((AbstractUserStoreManager) userStore.getUserStoreManager()).
                    authenticate(userStore.getDomainFreeName(), credential, domainProvided);
        }

        boolean authenticated;
        try (Secret credentialObj = Secret.getSecret(credential);) {
            authenticated = abstractUserStoreManager.doAuthenticate(userName, credentialObj);
        } catch (UnsupportedSecretTypeException e) {
            throw new DashboardUserStoreException(ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.getMessage(),
                    ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.getCode(), e);
        } catch (Exception e) {
            log.error("Error occurred while authenticating user: " + userName, e);
            throw new UserStoreException(ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(),
                    ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(), e);
        }

        if (!authenticated) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication failure. Wrong username or password is provided.");
            }
            throw new DashboardUserStoreException(ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(),
                    ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode());
        }
        return true;
    }

    /**
     * To validate username and credential that is given for authentication.
     *
     * @param userName   Name of the user.
     * @param credential Credential of the user.
     * @throws UserStoreException UserStore Exception on failure.
     */
    private void validateUserNameAndCredential(String userName, Object credential)
            throws DashboardUserStoreException {
        if (userName == null || credential == null) {
            String message = String.format(ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getMessage(),
                    "Authentication failure. Either Username or Password is null");
            log.error(message);
            // TODO: sabthar, remove DashboardUserStoreException
            throw new DashboardUserStoreException(message, ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getCode());
        }
    }

    @Override
    public String[] getRoleListOfUser(String userName) throws UserStoreException {
        try {
            UserStore userStore = getUserStore(userName);
            if (userStore.isRecursive()) {
                return userStore.getUserStoreManager().getRoleListOfUser(userStore.getDomainFreeName());
            }
            if (userStore.isSystemStore()) {
                return systemUserRoleManager.getSystemRoleListOfUser(userStore.getDomainFreeName());
            }
            return doGetRoleListOfUser(userName, "*");
        } catch (DashboardUserStoreException | org.wso2.micro.integrator.security.user.api.UserStoreException e) {
            throw new UserStoreException(e);
        }
    }

    public final String[] doGetRoleListOfUser(String userName, String filter) throws DashboardUserStoreException {
        if (!readGroupsEnabled) {
            return new String[0];
        }

        List<String> roles = new ArrayList<>();
        String[] externalRoles = doGetExternalRoleListOfUser(userName, "*");
        if (externalRoles != null) {
            roles.addAll(Arrays.asList(externalRoles));
        }
        if (isSharedGroupEnabled()) {
            String[] sharedRoles = doGetSharedRoleListOfUser(userName, null, "*");
            if (sharedRoles != null) {
                roles.addAll(Arrays.asList(sharedRoles));
            }
        }
        return UserStoreManagerUtils.addDomainToNames(roles.toArray(new String[0]), getMyDomainName());
    }

    public boolean isSharedGroupEnabled() {
        String value = realmConfig.getUserStoreProperty(SHARED_GROUPS_ENABLED);
        try {
            return realmConfig.isPrimary() && !isReadOnly() && TRUE_VALUE.equalsIgnoreCase(value);
        } catch (UserStoreException e) {
            log.error(e);
            return false;
        }
    }

    protected boolean checkUserNameValid(String userName) {
        if ((userName == null) || REGISTRY_SYSTEM_USERNAME.equals(userName)) {
            return false;
        }

        String allowLeadingOrTrailingSpace = realmConfig.getUserStoreProperty(LEADING_OR_TRAILING_SPACE_ALLOWED_IN_USERNAME);
        if (StringUtils.isEmpty(allowLeadingOrTrailingSpace)) {
            // Keeping old behavior for backward-compatibility.
            userName = userName.trim();
        } else if (log.isDebugEnabled()) {
            log.debug("'LeadingOrTrailingSpaceAllowedInUserName' property is set to : " +
                    allowLeadingOrTrailingSpace + ". Hence username trimming will be skipped during " +
                    "validation for the username: " + userName);
        }

        if (userName.isEmpty()) {
            return false;
        }

        String usernameRegex = realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG_EX);
        if (StringUtils.isEmpty(usernameRegex) || StringUtils.isEmpty(usernameRegex.trim())) {
            usernameRegex = realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG);
        }

        if (StringUtils.isNotEmpty(usernameRegex)) {
            usernameRegex = usernameRegex.trim();
            if (isFormatCorrect(usernameRegex, userName)) {
                return true;
            }
            if (log.isDebugEnabled()) {
                log.debug("Username " + userName + " does not match with the regex " + usernameRegex);
            }
            return false;
        }
        return true;
    }

    protected boolean checkUserPasswordValid(Object credential) throws DashboardUserStoreException {
        if (credential == null) {
            return false;
        }

        try (Secret credentialObj = Secret.getSecret(credential)) {
            if (credentialObj.getChars().length < 1) {
                return false;
            }
            String passwordRegex = realmConfig.getUserStoreProperty(PROPERTY_JAVA_REG_EX);
            if (passwordRegex != null) {
                if (isFormatCorrect(passwordRegex, credentialObj.getChars())) {
                    return true;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Submitted password does not match with the regex " + passwordRegex);
                }
                return false;
            }
            return true;
        } catch (UnsupportedSecretTypeException e) {
            throw new DashboardUserStoreException("Unsupported credential type", e);
        }
    }

    private boolean isFormatCorrect(String regularExpression, String attribute) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(attribute);
        return m2.matches();
    }

    private boolean isFormatCorrect(String regularExpression, char[] attribute) {
        CharBuffer charBuffer = CharBuffer.wrap(attribute);
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(charBuffer);
        return m2.matches();
    }

    private UserStore getUserStore(final String user) throws DashboardUserStoreException {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<UserStore>) ()
                    -> getUserStoreInternal(user));
        } catch (PrivilegedActionException e) {
            throw (DashboardUserStoreException) e.getException();
        }
    }

    private UserStore getUserStoreInternal(String user) throws UserStoreException {
        int index = user.indexOf(DOMAIN_SEPARATOR);
        UserStore userStore = new UserStore();
        String domain = getMyDomainName();
        userStore.setUserStoreManager(this);
        if (index > 0) {
            userStore.setDomainAwareName(user);
            userStore.setDomainFreeName(null);
        } else {
            userStore.setDomainAwareName(domain + DOMAIN_SEPARATOR + user);
            userStore.setDomainFreeName(user);
        }
        userStore.setRecursive(false);
        userStore.setDomainName(domain);
        return userStore;
    }

    protected String getMyDomainName() {
        return UserStoreManagerUtils.getDomainName(realmConfig);
    }

    /**
     * Only gets the external roles of the user.
     *
     * @param userName Name of the user - who we need to find roles.
     * @return
     * @throws UserStoreException
     */
    protected abstract String[] doGetExternalRoleListOfUser(String userName, String filter)
            throws DashboardUserStoreException;

    /**
     * Returns the shared roles list of the user
     *
     * @param userName
     * @return
     * @throws UserStoreException
     */
    protected abstract String[] doGetSharedRoleListOfUser(String userName, String tenantDomain, String filter)
            throws DashboardUserStoreException;

    /**
     * Given the username and a credential object, the implementation code must validate whether
     * the user is authenticated.
     *
     * @param userName   The username
     * @param credential The credential of a user
     * @return If the value is true the provided credential match with the username. False is
     * returned for invalid credential, invalid username and mismatching credential with
     * username.
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract boolean doAuthenticate(String userName, Object credential)
            throws DashboardUserStoreException;


    public final String[] listUsers(String filter, int maxItemLimit) throws UserStoreException {
        return doListUsers(filter, maxItemLimit);
    }

    protected abstract String[] doListUsers(String filter, int maxItemLimit)
            throws UserStoreException;
}
