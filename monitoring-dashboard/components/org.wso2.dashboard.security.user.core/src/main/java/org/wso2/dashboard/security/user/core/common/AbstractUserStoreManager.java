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
import org.wso2.micro.integrator.security.user.api.Permission;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserRealm;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.claim.ClaimMapping;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants;
import org.wso2.micro.integrator.security.user.core.hybrid.HybridRoleManager;
import org.wso2.micro.integrator.security.user.core.internal.UMListenerServiceComponent;
import org.wso2.micro.integrator.security.user.core.ldap.LDAPConstants;
import org.wso2.micro.integrator.security.user.core.listener.SecretHandleableListener;
import org.wso2.micro.integrator.security.user.core.listener.UserOperationEventListener;
import org.wso2.micro.integrator.security.user.core.multiplecredentials.UserAlreadyExistsException;
import org.wso2.micro.integrator.security.user.core.system.SystemUserRoleManager;
import org.wso2.micro.integrator.security.user.core.util.UserCoreUtil;

import javax.sql.DataSource;
import java.nio.CharBuffer;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.axis2.clustering.ClusteringConstants.Parameters.APPLICATION_DOMAIN;
import static org.wso2.carbon.user.core.UserCoreConstants.WORKFLOW_DOMAIN;
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
    private static final int MAX_ITEM_LIMIT_UNLIMITED = -1;


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
        } catch (org.wso2.micro.integrator.security.user.api.UserStoreException e) {
            throw new UserStoreException(e);
        }
    }

    public final String[] doGetRoleListOfUser(String userName, String filter) throws UserStoreException {
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

    protected boolean checkUserPasswordValid(Object credential) throws UserStoreException {
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
            throws UserStoreException;

    /**
     * Returns the shared roles list of the user
     *
     * @param userName
     * @return
     * @throws UserStoreException
     */
    protected abstract String[] doGetSharedRoleListOfUser(String userName, String tenantDomain, String filter)
            throws UserStoreException;

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
            throws UserStoreException;


    // TODO: sabthar, 2ndry user store - see code in MI
    public final String[] listUsers(String filter, int maxItemLimit) throws UserStoreException {
        return doListUsers(filter, maxItemLimit);
    }

    protected abstract String[] doListUsers(String filter, int maxItemLimit)
            throws UserStoreException;

    protected abstract RoleContext createRoleContext(String roleName) throws UserStoreException;

    @Override
    public void addUser(String userName, Object credential, String[] roleList,
                        Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        if (StringUtils.isEmpty(userName)) {
            String regEx = realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX);
            //Inorder to support both UsernameJavaRegEx and UserNameJavaRegEx.
            if (StringUtils.isEmpty(regEx) || StringUtils.isEmpty(regEx.trim())) {
                regEx = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG);
            }
            String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getMessage(), null, regEx);
            String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getCode();

            throw new UserStoreException(errorCode + " - " + message);
        }

        UserStore userStore = getUserStore(userName);

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.toString(), e);
        }

        try {
            if (userStore.isSystemStore()) {
                systemUserRoleManager.addSystemUser(userName, credentialObj, roleList);
                return;
            }

            // #################### Domain Name Free Zone Starts Here ################################

            if (isReadOnly()) {
                throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
            }
            // This happens only once during first startup - adding administrator user/role.
            // TODO: sabthar, fix the below comment
//            if (userName.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0) {
//                userName = userStore.getDomainFreeName();
//                roleList = UserCoreUtil.removeDomainFromNames(roleList);
//            }
            if (roleList == null) {
                roleList = new String[0];
            }
            if (claims == null) {
                claims = new HashMap<>();
            }

            if (!checkUserNameValid(userStore.getDomainFreeName())) {
                String regEx = realmConfig
                        .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX);
                //Inorder to support both UsernameJavaRegEx and UserNameJavaRegEx.
                if (StringUtils.isEmpty(regEx) || StringUtils.isEmpty(regEx.trim())) {
                    regEx = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG);
                }
                String message = String
                        .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getMessage(), userStore.getDomainFreeName(),
                                regEx);
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getCode();

                throw new UserStoreException(errorCode + " - " + message);
            }

            if (!checkUserPasswordValid(credentialObj)) {
                String regEx = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX);
                String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getMessage(), regEx);
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getCode();

                throw new UserStoreException(errorCode + " - " + message);
            }

            if (doCheckExistingUser(userStore.getDomainFreeName())) {
                String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_USER_ALREADY_EXISTS.getMessage(), userName);
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_USER_ALREADY_EXISTS.getCode();

                throw new UserAlreadyExistsException(errorCode + " - " + message);
            }

            List<String> internalRoles = new ArrayList<String>();
            List<String> externalRoles = new ArrayList<String>();
            int index;
            if (roleList != null) {
                for (String role : roleList) {
                    if (role != null && role.trim().length() > 0) {
                        // TODO: sabthar, fix this comment
//                        index = role.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
//                        if (index > 0) {
//                            String domain = role.substring(0, index);
//                            if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)) {
//                                internalRoles.add(UserCoreUtil.removeDomainFromName(role));
//                                continue;
//                            } else if (APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN
//                                    .equalsIgnoreCase(domain)) {
//                                internalRoles.add(role);
//                                continue;
//                            }
//                        }
//                        externalRoles.add(UserCoreUtil.removeDomainFromName(role));
                        externalRoles.add(role); // TODO: sabthar, added for testing
                    }
                }
            }

            // check existence of roles and claims before adding user
            for (String internalRole : internalRoles) {
                if (!hybridRoleManager.isExistingRole(internalRole)) {
                    String message = String
                            .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INTERNAL_ROLE_NOT_EXISTS.getMessage(), internalRole);
                    String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INTERNAL_ROLE_NOT_EXISTS.getCode();

                    throw new UserStoreException(errorCode + " - " + message);
                }
            }

            for (String externalRole : externalRoles) {
                if (!doCheckExistingRole(externalRole)) {
                    String message = String
                            .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_EXTERNAL_ROLE_NOT_EXISTS.getMessage(), externalRole);
                    String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_EXTERNAL_ROLE_NOT_EXISTS.getCode();

                    throw new UserStoreException(errorCode + " - " + message);
                }
            }

            if (claims != null) {
                for (Map.Entry<String, String> entry : claims.entrySet()) {
                    ClaimMapping claimMapping;
                    try {
                        claimMapping = (ClaimMapping) claimManager.getClaimMapping(entry.getKey());
                    } catch (org.wso2.micro.integrator.security.user.api.UserStoreException e) {
                        String errorMessage = String
                                .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNABLE_TO_FETCH_CLAIM_MAPPING.getMessage(),
                                        "persisting user attributes.");
                        String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNABLE_TO_FETCH_CLAIM_MAPPING.getCode();
                        throw new UserStoreException(errorCode + " - " + errorMessage, e);
                    }
                    if (claimMapping == null) {
                        String errorMessage = String
                                .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_CLAIM_URI.getMessage(), entry.getKey());
                        String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_CLAIM_URI.getCode();

                        throw new UserStoreException(errorCode + " - " + errorMessage);
                    }
                }
            }

            try {
                doAddUser(userName, credentialObj, externalRoles.toArray(new String[externalRoles.size()]), claims,
                        profileName, requirePasswordChange);
            } catch (UserStoreException ex) {

                throw ex;
            }

            if (internalRoles.size() > 0) {
                hybridRoleManager.updateHybridRoleListOfUser(userName, null,
                        internalRoles.toArray(new String[internalRoles.size()]));
            }

            try {
                for (UserOperationEventListener listener : UMListenerServiceComponent
                        .getUserOperationEventListeners()) {
                    Object credentialArgument;
                    if (listener instanceof SecretHandleableListener) {
                        credentialArgument = credentialObj;
                    } else {
                        credentialArgument = credential;
                    }

                    if (!listener.doPostAddUser(userName, credentialArgument, roleList, claims, profileName, this)) {

                        return;
                    }
                }
            } catch (UserStoreException ex) {

                throw ex;
            }
        } finally {
            credentialObj.clear();
        }

    }

    /**
     * @param userName
     * @return
     * @throws UserStoreException
     */
    protected abstract boolean doCheckExistingUser(String userName) throws UserStoreException;


    /**
     * Add a user to the user store.
     *
     * @param userName              User name of the user
     * @param credential            The credential/password of the user
     * @param roleList              The roles that user belongs
     * @param claims                Properties of the user
     * @param profileName           profile name, can be null. If null the default profile is considered.
     * @param requirePasswordChange whether password required is need
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void  doAddUser(String userName, Object credential, String[] roleList,
                                       Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException;


    /**
     * @param roleName
     * @return
     */
    protected abstract boolean doCheckExistingRole(String roleName) throws UserStoreException;


    /**
     * {@inheritDoc}
     */
    public final void deleteUser(String userName) throws UserStoreException {
        // #################### Domain Name Free Zone Starts Here ################################

        // TODO: sabthar, check this logic
//        if (UserCoreUtil.isPrimaryAdminUser(userName, realmConfig)) {
//            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DELETE_ADMIN_USER.toString());
//        }

        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DELETE_ANONYMOUS_USER.toString());
        }

        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        if (!doCheckExistingUser(userName)) {
            String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getMessage(), userName,
                    realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
            String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode();
            throw new UserStoreException(errorCode + " - " + errorMessage);
        }

        // Remove users from internal role mapping
//        hybridRoleManager.deleteUser(UserCoreUtil.addDomainToName(userName, getMyDomainName()));
        // TODO: sabthar, check the above logic

        doDeleteUser(userName);
    }

    /**
     * Delete the user with the given user name
     *
     * @param userName The user name
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doDeleteUser(String userName) throws UserStoreException;

    /**
     * {@inheritDoc}
     */
    public final void updateCredentialByAdmin(String userName, Object newCredential)
            throws UserStoreException {

        UserStore userStore = getUserStore(userName);

        // #################### Domain Name Free Zone Starts Here ################################
        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        org.wso2.micro.integrator.security.util.Secret newCredentialObj;
        try {
            newCredentialObj = org.wso2.micro.integrator.security.util.Secret.getSecret(newCredential);
        } catch (org.wso2.micro.integrator.security.UnsupportedSecretTypeException e) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.toString(), e);
        }

        try {

            if (!checkUserPasswordValid(newCredential)) {
//                    TODO: sabthar, check the below realm property
//                String errorMsg = realmConfig.getUserStoreProperty(PROPERTY_PASSWORD_ERROR_MSG);
                String errorMsg = "Invalid pattern in password";
                if (errorMsg != null) {
                    String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_DURING_PRE_UPDATE_CREDENTIAL_BY_ADMIN.getCode();
                    String errorMessage = String
                            .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_DURING_PRE_UPDATE_CREDENTIAL_BY_ADMIN.getMessage(),
                                    errorMsg);
                    throw new UserStoreException(errorCode + " - " + errorMessage);
                }

                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getCode();
                String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getMessage(),
                        realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));
                throw new UserStoreException(errorCode + " - " + errorMessage);
            }

            if (!doCheckExistingUser(userStore.getDomainFreeName())) {
                String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getMessage(), userName,
                        realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode();
                throw new UserStoreException(errorCode + "-" + errorMessage);
            }

            try {
                doUpdateCredentialByAdmin(userName, newCredentialObj);
            } catch (UserStoreException ex) {
                throw ex;
            }
        } finally {
            newCredentialObj.clear();
        }
        // #################### </Listeners> #####################################################

    }


    /**
     * {@inheritDoc}
     */
    public final void updateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

       Secret newCredentialObj;
        Secret oldCredentialObj;
        try {
            newCredentialObj = Secret.getSecret(newCredential);
            oldCredentialObj =Secret.getSecret(oldCredential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.toString());
        }

        // #################### <Listeners> #####################################################
        try {

            // This user name here is domain-less.
            // We directly authenticate user against the selected UserStoreManager.
            boolean isAuth = this.doAuthenticate(userName, oldCredentialObj);

            if (isAuth) {
                if (!checkUserPasswordValid(newCredential)) {
//                    TODO: sabthar, check the below realm property
//                    String errorMsg = realmConfig.getUserStoreProperty(PROPERTY_PASSWORD_ERROR_MSG);
                    String errorMsg = "Invalid pattern in password";
                    if (errorMsg != null) {
                        String errorMessage = String
                                .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_DURING_PRE_UPDATE_CREDENTIAL.getMessage(),
                                        errorMsg);
                        String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_DURING_PRE_UPDATE_CREDENTIAL.getCode();
                        throw new UserStoreException(errorCode + " - " + errorMessage);
                    }

                    String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getMessage(),
                            realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));
                    String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getCode();
                    throw new UserStoreException(errorCode + " - " + errorMessage);
                }

                try {
                    this.doUpdateCredential(userName, newCredentialObj, oldCredentialObj);
                } catch (UserStoreException ex) {
                    throw ex;
                }



            } else {
                throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_OLD_CREDENTIAL_DOES_NOT_MATCH.toString());
            }
        } finally {
            newCredentialObj.clear();
            oldCredentialObj.clear();
        }
    }



    /**
     * Update credential/password by the admin of another user
     *
     * @param userName      The user name
     * @param newCredential The new credential
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doUpdateCredentialByAdmin(String userName, Object newCredential)
            throws UserStoreException;

    /**
     * Update the credential/password of the user
     *
     * @param userName      The user name
     * @param newCredential The new credential/password
     * @param oldCredential The old credential/password
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doUpdateCredential(String userName, Object newCredential,
                                               Object oldCredential) throws UserStoreException;


    /**
     *
     */
    public void addRole(String roleName, String[] userList, Permission[] permissions, boolean isSharedRole)
            throws org.wso2.micro.integrator.security.user.api.UserStoreException {

        if (StringUtils.isEmpty(roleName)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_ADD_EMPTY_ROLE.toString());
        }

        UserStore userStore = getUserStore(roleName);

        if (isSharedRole && !isSharedGroupEnabled()) {
            throw new UserStoreException(
                    UserCoreErrorConstants.ErrorMessages.ERROR_CODE_SHARED_ROLE_NOT_SUPPORTED.toString());
        }



        // #################### Domain Name Free Zone Starts Here ################################
        if (userList == null) {
            userList = new String[0];
        }
        if (permissions == null) {
            permissions = new Permission[0];
        }
        // This happens only once during first startup - adding administrator user/role.
        // TODO: sabthar, check domain, needed here
//        if (roleName.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0) {
//            roleName = userStore.getDomainFreeName();
//            userList = UserCoreUtil.removeDomainFromNames(userList);
//        }

        // Check for validations
        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        if (!isRoleNameValid(roleName)) {
            String regEx = realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
            String errorMessage = String
                    .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_ROLE_NAME.getMessage(), roleName, regEx);
            String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_ROLE_NAME.getCode();
           throw new UserStoreException(errorCode + " - " + errorMessage);
        }

        if (doCheckExistingRole(roleName)) {
            handleRoleAlreadyExistException(roleName, userList, permissions);
        }

//        String roleWithDomain = null;
        // TODO: sabhtar, what is this write gropus
        if (writeGroupsEnabled) {
            try {
                // add role in to actual user store
                doAddRole(roleName, userList, isSharedRole);
//                roleWithDomain = UserCoreUtil.addDomainToName(roleName, getMyDomainName());
            } catch (UserStoreException ex) {
                throw ex;
            }
        } else {
           throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_WRITE_GROUPS_NOT_ENABLED.toString());
        }

        // add permission in to the the permission store
        if (permissions != null) {
            for (Permission permission : permissions) {
                String resourceId = permission.getResourceId();
                String action = permission.getAction();
                if (resourceId == null || resourceId.trim().length() == 0) {
                    continue;
                }

                if (action == null || action.trim().length() == 0) {
                    // default action value // TODO
                    action = "read";
                }
                // This is a special case. We need to pass domain aware name.
//                userRealm.getAuthorizationManager().authorizeRole(roleWithDomain, resourceId,
//                        action);
            }
        }


    }

    /**
     * @param roleName
     * @return
     */
    protected boolean isRoleNameValid(String roleName) {
        if (roleName == null) {
            return false;
        }

        if (roleName.length() < 1) {
            return false;
        }

        String regularExpression = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
        if (regularExpression != null) {
            if (!isFormatCorrect(regularExpression, roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * This method handles role already exists exception.
     *
     * @param roleName    Name of teh role.
     * @param userList    list of users.
     * @param permissions Relevant permissions added for new role.
     * @throws UserStoreException User Store Exception.
     */
    private void handleRoleAlreadyExistException(String roleName, String[] userList, Permission[] permissions) throws UserStoreException {

        String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ROLE_ALREADY_EXISTS.getCode();
        String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ROLE_ALREADY_EXISTS.getMessage(), roleName);
      throw new UserStoreException(errorCode + " - " + errorMessage);
    }

    /**
     * Add role with a list of users and permissions provided.
     *
     * @param roleName
     * @param userList
     * @throws UserStoreException
     */
    protected abstract void doAddRole(String roleName, String[] userList, boolean shared) throws UserStoreException;


    /**
     * {@inheritDoc}
     */
    public final String[] getRoleNames() throws UserStoreException {
        return getRoleNames(false);
    }

    /**
     * {@inheritDoc}
     */
    public final String[] getRoleNames(boolean noHybridRoles) throws UserStoreException {
        return getRoleNames("*", MAX_ITEM_LIMIT_UNLIMITED, noHybridRoles, true, true);
    }

    /**
     * TODO This method would returns the role Name actually this must be implemented in interface.
     * As it is not good to change the API in point release. This has been added to Abstract class
     *
     * @param filter
     * @param maxItemLimit
     * @param noInternalRoles
     * @return
     * @throws UserStoreException
     */
    public final String[] getRoleNames(String filter, int maxItemLimit, boolean noInternalRoles,
                                       boolean noSystemRole, boolean noSharedRoles)
            throws UserStoreException {

        String[] roleList = new String[0];
        // TODO: sabhtar, what is this read group
        if (readGroupsEnabled) {
            String[] externalRoles = doGetRoleNames(filter, maxItemLimit);
            roleList = UserCoreUtil.combineArrays(externalRoles, roleList);
        }
        return roleList;
    }

    /**
     * This method would returns the role Name actually this must be implemented in interface. As it
     * is not good to change the API in point release. This has been added to Abstract class
     *
     * @param filter
     * @param maxItemLimit
     * @return
     * @throws .UserStoreException
     */
    protected abstract String[] doGetRoleNames(String filter, int maxItemLimit)
            throws UserStoreException;


    /**
     * {@inheritDoc}
     */
    public final String[] getUserListOfRole(String roleName) throws UserStoreException {


        String[] userNames = new String[0];

        // If role does not exit, just return
        if (!isExistingRole(roleName)) {
            return userNames;
        }



        if (readGroupsEnabled) {
            userNames = doGetUserListOfRole(roleName, "*");
        }

        return userNames;
    }



    /**
     * @param roleName
     * @param filter
     * @return
     * @throws UserStoreException
     */
    protected abstract String[] doGetUserListOfRole(String roleName, String filter)
            throws UserStoreException;

}
