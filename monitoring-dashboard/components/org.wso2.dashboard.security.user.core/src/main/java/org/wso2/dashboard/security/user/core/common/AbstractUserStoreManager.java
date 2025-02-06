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
import org.wso2.micro.integrator.security.user.api.Permission;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants.RealmConfig;
import org.wso2.micro.integrator.security.user.core.UserRealm;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.claim.ClaimMapping;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants;
import org.wso2.micro.integrator.security.user.core.hybrid.HybridRoleManager;
import org.wso2.micro.integrator.security.user.core.internal.UMListenerServiceComponent;
import org.wso2.micro.integrator.security.user.core.listener.SecretHandleableListener;
import org.wso2.micro.integrator.security.user.core.listener.UserOperationEventListener;
import org.wso2.micro.integrator.security.user.core.multiplecredentials.UserAlreadyExistsException;
import org.wso2.micro.integrator.security.user.core.util.UserCoreUtil;

import javax.sql.DataSource;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.dashboard.security.user.core.UserStoreConstants.REGISTRY_SYSTEM_USERNAME;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.LEADING_OR_TRAILING_SPACE_ALLOWED_IN_USERNAME;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.SHARED_GROUPS_ENABLED;
import static org.wso2.micro.integrator.security.user.core.UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED;
import static org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants.ErrorMessages.*;

public abstract class AbstractUserStoreManager implements UserStoreManager {
    private static final Log log = LogFactory.getLog(AbstractUserStoreManager.class);
    private static final String TRUE_VALUE = "true";
    private static final int MAX_ITEM_LIMIT_UNLIMITED = -1;
    protected int tenantId;
    protected DataSource dataSource = null;
    protected RealmConfiguration realmConfig = null;
    protected ClaimManager claimManager = null;
    protected UserRealm userRealm = null;
    protected HybridRoleManager hybridRoleManager = null;
    protected boolean readGroupsEnabled = false;
    protected boolean writeGroupsEnabled = false;

    @Override
    public boolean authenticate(final String username, final Object credential) {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                validateUserNameAndCredential(username, credential);
                return authenticateInternal(username, credential);
            });
        } catch (PrivilegedActionException e) {
            throw new RuntimeException("Error during authentication", e);
        }
    }

    private boolean authenticateInternal(String username, Object credential) throws UserStoreException {
        try (Secret credentialObj = Secret.getSecret(credential)) {
            boolean authenticated = this.doAuthenticate(username, credentialObj);
            if (authenticated) {
                return true;
            }
        } catch (UnsupportedSecretTypeException e) {
            throw new DashboardUserStoreException(ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.getMessage(),
                    ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.getCode(), e);
        } catch (Exception e) {
            log.error("Error occurred while authenticating user: " + username, e);
            throw new UserStoreException(ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(),
                    ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Authentication failure. Wrong username or password is provided.");
        }
        throw new DashboardUserStoreException(ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(),
                ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode());
    }

    /**
     * Given the username and a credential object, the implementation code must validate whether
     * the user is authenticated.
     *
     * @param username   The username
     * @param credential The credential of a user
     * @return If the value is true the provided credential match with the username. False is
     * returned for invalid credential, invalid username and mismatching credential with
     * username.
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract boolean doAuthenticate(String username, Object credential)
            throws UserStoreException;

    /**
     * To validate username and credential that is given for authentication.
     *
     * @param username   Name of the user.
     * @param credential Credential of the user.
     * @throws UserStoreException UserStore Exception on failure.
     */
    private void validateUserNameAndCredential(String username, Object credential) throws UserStoreException {
        if (username == null || credential == null) {
            String message = String.format(ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getMessage(),
                    "Authentication failure. Either Username or Password is null");
            log.error(message);
            throw new DashboardUserStoreException(message, ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getCode());
        }
    }

    public final String[] listUsers(String filter, int maxItemLimit) throws UserStoreException {
        return doListUsers(filter, maxItemLimit);
    }

    protected abstract String[] doListUsers(String filter, int maxItemLimit)
            throws UserStoreException;

    /**
     * {@inheritDoc}
     */
    public boolean isExistingRole(String roleName) throws UserStoreException {
        return doCheckExistingRole(roleName);
    }

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

    @Override
    public String[] getRoleListOfUser(String username) throws UserStoreException {
        return doGetRoleListOfUser(username, "*");
    }

    public final String[] doGetRoleListOfUser(String username, String filter) throws UserStoreException {
        // TODO: sabthar, what is this read groups and shared groups
        if (!readGroupsEnabled) {
            return new String[0];
        }

        List<String> roles = new ArrayList<>();
        String[] externalRoles = doGetExternalRoleListOfUser(username, filter);
        if (externalRoles != null) {
            roles.addAll(Arrays.asList(externalRoles));
        }
        if (isSharedGroupEnabled()) {
            String[] sharedRoles = doGetSharedRoleListOfUser(username, null, filter);
            if (sharedRoles != null) {
                roles.addAll(Arrays.asList(sharedRoles));
            }
        }
        return roles.toArray(new String[0]);
    }

    // TODO: sabthar, what is this shared group
    public boolean isSharedGroupEnabled() {
        try {
            String value = realmConfig.getUserStoreProperty(SHARED_GROUPS_ENABLED);
            return realmConfig.isPrimary() && !isReadOnly() && TRUE_VALUE.equalsIgnoreCase(value);
        } catch (UserStoreException e) {
            log.error(e);
            return false;
        }
    }

    /**
     * Only gets the external roles of the user.
     *
     * @param username Name of the user - who we need to find roles.
     * @return
     * @throws UserStoreException
     */
    protected abstract String[] doGetExternalRoleListOfUser(String username, String filter)
            throws UserStoreException;

    /**
     * Returns the shared roles list of the user
     *
     * @param username
     * @return
     * @throws UserStoreException
     */
    protected abstract String[] doGetSharedRoleListOfUser(String username, String tenantDomain, String filter)
            throws UserStoreException;

    /**
     * {@inheritDoc}
     */
    public final String[] getUserListOfRole(String roleName) throws UserStoreException {


        String[] usernames = new String[0];

        // If role does not exit, just return
        if (!isExistingRole(roleName)) {
            return usernames;
        }


        if (readGroupsEnabled) {
            usernames = doGetUserListOfRole(roleName, "*");
        }

        return usernames;
    }

    protected abstract String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException;

    @Override
    public void addUser(String username, Object credential, String[] roleList,
                        Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        if (StringUtils.isEmpty(username)) {
            String regEx = realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX);
            //Inorder to support both UsernameJavaRegEx and UserNameJavaRegEx.
            if (StringUtils.isEmpty(regEx) || StringUtils.isEmpty(regEx.trim())) {
                regEx = realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_USER_NAME_JAVA_REG);
            }
            String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getMessage(), null, regEx);
            String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getCode();
            throw new UserStoreException(errorCode + " - " + message);
        }

        try (Secret credentialObj = Secret.getSecret(credential);) {
            if (isReadOnly()) {
                throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
            }
            if (roleList == null) {
                roleList = new String[0];
            }
            if (claims == null) {
                claims = new HashMap<>();
            }

            if (!isValidUsername(username)) {
                String regEx = realmConfig
                        .getUserStoreProperty(RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX);
                //Inorder to support both UsernameJavaRegEx and UserNameJavaRegEx.
                if (StringUtils.isEmpty(regEx) || StringUtils.isEmpty(regEx.trim())) {
                    regEx = realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_USER_NAME_JAVA_REG);
                }
                String message = String
                        .format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getMessage(), username,
                                regEx);
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_USER_NAME.getCode();

                throw new UserStoreException(errorCode + " - " + message);
            }

            if (!isValidPassword(credentialObj)) {
                String regEx = realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_JAVA_REG_EX);
                String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getMessage(), regEx);
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getCode();

                throw new UserStoreException(errorCode + " - " + message);
            }

            if (doCheckExistingUser(username)) {
                String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_USER_ALREADY_EXISTS.getMessage(), username);
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_USER_ALREADY_EXISTS.getCode();

                throw new UserAlreadyExistsException(errorCode + " - " + message);
            }

            List<String> internalRoles = new ArrayList<>();
            List<String> externalRoles = new ArrayList<>();
//            int index;
            if (roleList != null) {
                for (String role : roleList) {
                    if (role != null && role.trim().length() > 0) {
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
                doAddUser(username, credentialObj, externalRoles.toArray(new String[externalRoles.size()]), claims,
                        profileName, requirePasswordChange);
            } catch (UserStoreException ex) {

                throw ex;
            }

            if (internalRoles.size() > 0) {
                hybridRoleManager.updateHybridRoleListOfUser(username, null,
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

                    if (!listener.doPostAddUser(username, credentialArgument, roleList, claims, profileName, this)) {

                        return;
                    }
                }
            } catch (UserStoreException ex) {

                throw ex;
            }
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.toString(), e);
        }

    }

    protected boolean isValidUsername(String username) {
        // TODO: sabthar, what is this registry system username
        if ((username == null) || REGISTRY_SYSTEM_USERNAME.equals(username)) {
            return false;
        }

        String allowLeadingOrTrailingSpace = realmConfig.getUserStoreProperty(LEADING_OR_TRAILING_SPACE_ALLOWED_IN_USERNAME);
        if (StringUtils.isEmpty(allowLeadingOrTrailingSpace)) {
            // Keeping old behavior for backward-compatibility.
            username = username.trim();
        } else if (log.isDebugEnabled()) {
            log.debug("'LeadingOrTrailingSpaceAllowedInUserName' property is set to : " +
                    allowLeadingOrTrailingSpace + ". Hence username trimming will be skipped during " +
                    "validation for the username: " + username);
        }

        if (username.isEmpty()) {
            return false;
        }

        String usernameRegex = realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG_EX);
        if (StringUtils.isEmpty(usernameRegex) || StringUtils.isEmpty(usernameRegex.trim())) {
            usernameRegex = realmConfig.getUserStoreProperty(PROPERTY_USER_NAME_JAVA_REG);
        }

        if (StringUtils.isNotEmpty(usernameRegex)) {
            usernameRegex = usernameRegex.trim();
            if (hasValidFormat(usernameRegex, username)) {
                return true;
            }
            if (log.isDebugEnabled()) {
                log.debug("Username " + username + " does not match with the regex " + usernameRegex);
            }
            return false;
        }
        return true;
    }

    private boolean hasValidFormat(String regularExpression, String attribute) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(attribute);
        return m2.matches();
    }

    protected boolean isValidPassword(Object credential) throws UserStoreException {
        if (credential == null) {
            return false;
        }

        try (Secret credentialObj = Secret.getSecret(credential)) {
            if (credentialObj.getChars().length < 1) {
                return false;
            }
            String passwordRegex = realmConfig.getUserStoreProperty(PROPERTY_JAVA_REG_EX);
            if (passwordRegex != null) {
                if (hasValidFormat(passwordRegex, credentialObj.getChars())) {
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

    private boolean hasValidFormat(String regularExpression, char[] attribute) {
        return hasValidFormat(regularExpression, String.valueOf(attribute));
    }

    /**
     * @param username
     * @return
     * @throws UserStoreException
     */
    protected abstract boolean doCheckExistingUser(String username) throws UserStoreException;

    /**
     * Add a user to the user store.
     *
     * @param username              User name of the user
     * @param credential            The credential/password of the user
     * @param roleList              The roles that user belongs
     * @param claims                Properties of the user
     * @param profileName           profile name, can be null. If null the default profile is considered.
     * @param requirePasswordChange whether password required is need
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doAddUser(String username, Object credential, String[] roleList,
                                      Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException;

    /**
     * {@inheritDoc}
     */
    public final void updateCredential(String username, Object newCredential, Object oldCredential)
            throws UserStoreException {

        // #################### Domain Name Free Zone Starts Here ################################

        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        Secret newCredentialObj;
        Secret oldCredentialObj;
        try {
            newCredentialObj = Secret.getSecret(newCredential);
            oldCredentialObj = Secret.getSecret(oldCredential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.toString());
        }

        // #################### <Listeners> #####################################################
        try {

            // This user name here is domain-less.
            // We directly authenticate user against the selected UserStoreManager.
            boolean isAuth = this.doAuthenticate(username, oldCredentialObj);

            if (isAuth) {
                if (!isValidPassword(newCredential)) {
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
                            realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_JAVA_REG_EX));
                    String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_INVALID_PASSWORD.getCode();
                    throw new UserStoreException(errorCode + " - " + errorMessage);
                }

                try {
                    this.doUpdateCredential(username, newCredentialObj, oldCredentialObj);
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
     * {@inheritDoc}
     */
    public final void updateCredentialByAdmin(String username, Object newCredential)
            throws UserStoreException {

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

            if (!isValidPassword(newCredential)) {
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
                        realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_JAVA_REG_EX));
                throw new UserStoreException(errorCode + " - " + errorMessage);
            }

            if (!doCheckExistingUser(username)) {
                String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getMessage(), username,
                        realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_DOMAIN_NAME));
                String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode();
                throw new UserStoreException(errorCode + "-" + errorMessage);
            }

            try {
                doUpdateCredentialByAdmin(username, newCredentialObj);
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
    public final void deleteUser(String username) throws UserStoreException {
        if (realmConfig.getAdminUserName().equals(username)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DELETE_ADMIN_USER.toString());
        }

        if (UserCoreUtil.isRegistryAnnonymousUser(username)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DELETE_ANONYMOUS_USER.toString());
        }

        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        if (!doCheckExistingUser(username)) {
            String errorMessage = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getMessage(), username,
                    realmConfig.getUserStoreProperty(RealmConfig.PROPERTY_DOMAIN_NAME));
            String errorCode = UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode();
            throw new UserStoreException(errorCode + " - " + errorMessage);
        }
        doDeleteUser(username);
    }

    /**
     * Delete the user with the given user name
     *
     * @param username The user name
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doDeleteUser(String username) throws UserStoreException;

    /**
     * Delete the role with the given role name
     *
     * @param roleName The role name
     * @throws UserStoreException
     */
    public final void deleteRole(String roleName) throws UserStoreException {


        if (realmConfig.getAdminRoleName().equalsIgnoreCase(roleName)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_DELETE_ADMIN_ROLE.toString());
        }

        if (!doCheckExistingRole(roleName)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_DELETE_NON_EXISTING_ROLE.toString());
        }


        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        if (!writeGroupsEnabled) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_WRITE_GROUPS_NOT_ENABLED.toString());
        }
        try {
            doDeleteRole(roleName);
        } catch (UserStoreException ex) {
            throw ex;
        }

    }

    public final void updateRoleListOfUser(final String username, final String[] deletedRoles, final String[] newRoles)
            throws UserStoreException {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<String>() {
                @Override
                public String run() throws Exception {
                    updateRoleListOfUserInternal(username, deletedRoles, newRoles);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }
    }

    /**
     * {@inheritDoc}
     */
    private final void updateRoleListOfUserInternal(String username, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {


        if (deletedRoles != null && deletedRoles.length > 0) {
            Arrays.sort(deletedRoles);
            if (realmConfig.getAdminUserName().equals(username)) {
                for (String deletedRole : deletedRoles) {
                    if (deletedRole.equalsIgnoreCase(realmConfig.getAdminRoleName())) {
                        throw new UserStoreException(ERROR_CODE_CANNOT_REMOVE_ADMIN_ROLE_FROM_ADMIN.toString());
                    }
                }
            }
        }

        if (deletedRoles == null) {
            deletedRoles = new String[0];
        }
        if (newRoles == null) {
            newRoles = new String[0];
        }

        List<String> roleDel = new ArrayList<String>();
        List<String> roleNew = new ArrayList<String>();

        if (deletedRoles.length > 0) {
            for (String deleteRole : deletedRoles) {
//                TODO: sabthar, what is this is everyone role
//                if (UserCoreUtil.isEveryoneRole(deleteRole, realmConfig)) {
//                    handleUpdateRoleListOfUserFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_UPDATE_EVERYONE_ROLE.getCode(),
//                            UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_UPDATE_EVERYONE_ROLE.getMessage(), username, deletedRoles,
//                            newRoles);
//                    throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_UPDATE_EVERYONE_ROLE.toString());
//                }
//                String domain = null;
//                int index1 = deleteRole.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
//                if (index1 > 0) {
//                    domain = deleteRole.substring(0, index1);
//                }
//                if (APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
//                    internalRoleDel.add(deleteRole);
//                } else if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain) || this.isReadOnly()) {
//                    internalRoleDel.add(UserCoreUtil.removeDomainFromName(deleteRole));
//                } else {
                // This is domain free role name.
                roleDel.add(deleteRole);
//                }
            }
            deletedRoles = roleDel.toArray(new String[roleDel.size()]);
        }

        if (newRoles.length > 0) {
            for (String newRole : newRoles) {
//                if (UserCoreUtil.isEveryoneRole(newRole, realmConfig)) {
//                    handleUpdateRoleListOfUserFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_UPDATE_EVERYONE_ROLE.getCode(),
//                            UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_UPDATE_EVERYONE_ROLE.getMessage(), username, deletedRoles,
//                            newRoles);
//                    throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_UPDATE_EVERYONE_ROLE.toString());
//                }
//                String domain = null;
//                int index2 = newRole.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
//                if (index2 > 0) {
//                    domain = newRole.substring(0, index2);
//                }
//
//                if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)) {
//                    // If this is an internal role.
//                    internalRoleNew.add(UserCoreUtil.removeDomainFromName(newRole));
//                } else if (APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
//                    // If this is an application role or workflow role.
//                    internalRoleNew.add(newRole);
//                } else if (this.isReadOnly()) {
//                    // If this is a readonly user store, we add even normal roles as internal roles.
//                    internalRoleNew.add(UserCoreUtil.removeDomainFromName(newRole));
//                } else {
                roleNew.add(newRole);
//                }
            }
            newRoles = roleNew.toArray(new String[roleNew.size()]);
        }

//        if (internalRoleDel.size() > 0 || internalRoleNew.size() > 0) {
//            hybridRoleManager.updateHybridRoleListOfUser(userStore.getDomainFreeName(),
//                    internalRoleDel.toArray(new String[internalRoleDel.size()]),
//                    internalRoleNew.toArray(new String[internalRoleNew.size()]));
//        }

        if (deletedRoles.length > 0 || newRoles.length > 0) {
            if (!isReadOnly() && writeGroupsEnabled) {
                doUpdateRoleListOfUser(username, deletedRoles, newRoles);
            } else {
                throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
            }
        }
    }

    /**
     * Update role list of a particular user
     *
     * @param username     The user name
     * @param deletedRoles Array of role names, that is going to be removed from the user
     * @param newRoles     Array of role names, that is going to be added to the user
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doUpdateRoleListOfUser(String username, String[] deletedRoles,
                                                   String[] newRoles) throws UserStoreException;

    @Override
    public final String[] getHybridRoles() throws UserStoreException {
        throw new UnsupportedOperationException();
    }

    protected abstract void doDeleteRole(String roleName) throws UserStoreException;

    /**
     * Update credential/password by the admin of another user
     *
     * @param username      The user name
     * @param newCredential The new credential
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doUpdateCredentialByAdmin(String username, Object newCredential)
            throws UserStoreException;

    /**
     * Update the credential/password of the user
     *
     * @param username      The user name
     * @param newCredential The new credential/password
     * @param oldCredential The old credential/password
     * @throws UserStoreException An unexpected exception has occurred
     */
    protected abstract void doUpdateCredential(String username, Object newCredential,
                                               Object oldCredential) throws UserStoreException;

    /**
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
     * @param roleName
     * @return
     */
    protected abstract boolean doCheckExistingRole(String roleName) throws UserStoreException;

    protected abstract RoleContext createRoleContext(String roleName) throws UserStoreException;

    /**
     *
     */
    public void addRole(String roleName, String[] userList, Permission[] permissions, boolean isSharedRole)
            throws org.wso2.micro.integrator.security.user.api.UserStoreException {

        if (StringUtils.isEmpty(roleName)) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_CANNOT_ADD_EMPTY_ROLE.toString());
        }

        if (isSharedRole && !isSharedGroupEnabled()) {
            throw new UserStoreException(
                    UserCoreErrorConstants.ErrorMessages.ERROR_CODE_SHARED_ROLE_NOT_SUPPORTED.toString());
        }

        if (userList == null) {
            userList = new String[0];
        }
        if (permissions == null) {
            permissions = new Permission[0];
        }
        // Check for validations
        if (isReadOnly()) {
            throw new UserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_READONLY_USER_STORE.toString());
        }

        if (!isRoleNameValid(roleName)) {
            String regEx = realmConfig
                    .getUserStoreProperty(RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
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
                .getUserStoreProperty(RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
        if (regularExpression != null) {
            if (!hasValidFormat(regularExpression, roleName)) {
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
     * @param username
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public boolean isUserInRole(String username, String roleName) throws UserStoreException {

        if (roleName == null || roleName.trim().length() == 0 || username == null ||
                username.trim().length() == 0) {
            return false;
        }

        String[] roles = null;

        boolean success = false;
        if (readGroupsEnabled) {
            success = doCheckIsUserInRole(username, roleName);
        }

        // add to cache
        if (success) {
            String modifiedUserName = UserCoreConstants.IS_USER_IN_ROLE_CACHE_IDENTIFIER + username;
            addToIsUserHasRole(modifiedUserName, roleName, roles);
        }
        return success;
    }

    /**
     * @param username
     * @param roleName
     * @return
     * @throws UserStoreException
     */
    public abstract boolean doCheckIsUserInRole(String username, String roleName) throws UserStoreException;

    /**
     * Helper method
     *
     * @param username
     * @param roleName
     * @param currentRoles
     */
    private void addToIsUserHasRole(String username, String roleName, String[] currentRoles) {
        List<String> roles;
        if (currentRoles != null) {
            roles = new ArrayList<String>(Arrays.asList(currentRoles));
        } else {
            roles = new ArrayList<String>();
        }
        roles.add(roleName);
    }

    protected void addInitialAdminData(boolean addAdmin) throws UserStoreException {
        String adminUsername = realmConfig.getAdminUserName();
        String adminRoleName = realmConfig.getAdminRoleName();

        if (adminUsername == null || adminRoleName == null) {
            String errorMessage = "Admin user name or role name is not valid. Please provide valid values.";
            log.error(errorMessage);
            throw new UserStoreException(errorMessage);
        }

        boolean userExist = checkRoleExistence(adminUsername);
        boolean roleExist = checkUserExistence(adminRoleName);

        if (!userExist) {
            handleAdminUserCreation(adminUsername, addAdmin);
        }

        if (!roleExist) {
            handleAdminRoleCreation(adminRoleName, adminUsername, addAdmin);
        }

        assignUserToRole(adminUsername, adminRoleName, addAdmin);
    }

    private boolean checkRoleExistence(String roleName) {
        try {
            if (Boolean.parseBoolean(this.getRealmConfiguration().getUserStoreProperty(READ_GROUPS_ENABLED))) {
                return doCheckExistingRole(roleName);
            }
        } catch (Exception e) {
            log.debug("Error while checking role existence: " + e.getMessage(), e);
        }
        return false;
    }

    private boolean checkUserExistence(String username) {
        try {
            return doCheckExistingUser(username);
        } catch (Exception e) {
            log.debug("Error while checking user existence: " + e.getMessage(), e);
        }
        return false;
    }

    private void handleAdminUserCreation(String adminUsername, boolean addAdmin) throws UserStoreException {
        if (!isReadOnly() && addAdmin) {
            try {
                doAddUser(adminUsername, realmConfig.getAdminPassword(), null, null, null, false);
            } catch (Exception e) {
                log.error("Admin user has not been created. Error occurred while creating admin user.", e);
            }
        }
    }

    private void handleAdminRoleCreation(String adminRoleName, String adminUsername, boolean addAdmin) throws UserStoreException {
        if (addAdmin) {
            if (!isReadOnly() && writeGroupsEnabled) {
                try {
                    doAddRole(adminRoleName, new String[]{adminUsername}, false);
                } catch (UserStoreException e) {
                    log.error("Admin role has not been created. Error occurred while creating admin role.", e);
                }
            }
        } else {
            log.error("Admin role cannot be created. Add-Admin is set to false. Please use an existing role as the admin role.");
        }
    }

    private void assignUserToRole(String adminUsername, String adminRoleName, boolean addAdmin) throws UserStoreException {
        if (!isReadOnly() && writeGroupsEnabled) {
            try {
                if (!doCheckIsUserInRole(adminUsername, adminRoleName)) {
                    if (addAdmin) {
                        doUpdateRoleListOfUser(adminUsername, null, new String[]{adminRoleName});
                    } else {
                        log.error("Admin user cannot be assigned to admin role. Add-Admin is set to false. Please assign the role manually.");
                    }
                }
            } catch (Exception e) {
                log.error("Error while assigning admin user to admin role.", e);
            }
        }
    }
}
