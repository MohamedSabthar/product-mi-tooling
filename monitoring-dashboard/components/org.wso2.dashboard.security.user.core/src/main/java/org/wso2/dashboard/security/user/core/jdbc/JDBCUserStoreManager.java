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

package org.wso2.dashboard.security.user.core.jdbc;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dashboard.security.user.core.DatabaseUtil;
import org.wso2.dashboard.security.user.core.UserStoreConstants;
import org.wso2.dashboard.security.user.core.common.AbstractUserStoreManager;
import org.wso2.dashboard.security.user.core.common.DashboardUserStoreException;
import org.wso2.dashboard.security.user.core.common.RoleBreakdown;
import org.wso2.dashboard.security.user.core.common.Secret;
import org.wso2.dashboard.security.user.core.common.UnsupportedSecretTypeException;
import org.wso2.micro.core.util.DatabaseCreator;
import org.wso2.micro.integrator.security.user.api.ClaimManager;
import org.wso2.micro.integrator.security.user.api.Permission;
import org.wso2.micro.integrator.security.user.api.Properties;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.security.user.core.claim.Claim;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants;
import org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants;
import org.wso2.micro.integrator.security.user.core.jdbc.JDBCRoleContext;
import org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants;
import org.wso2.micro.integrator.security.user.core.ldap.LDAPConstants;
import org.wso2.micro.integrator.security.user.core.tenant.Tenant;
import org.wso2.micro.integrator.security.user.core.util.JDBCRealmUtil;

import javax.sql.DataSource;
import javax.validation.constraints.NotNull;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.SQLTimeoutException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.READ_GROUPS_ENABLED;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.WRITE_GROUPS_ENABLED;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.DIGEST_FUNCTION;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.GET_IS_USER_ROLE_EXIST;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.GET_USER_FILTER;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.GET_USER_ROLE;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.SELECT_USER;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.STORE_SALTED_PASSWORDS;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.GET_IS_USER_ROLE_EXIST_CASE_INSENSITIVE;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.GET_USER_FILTER_CASE_INSENSITIVE;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.GET_USER_ROLE_CASE_INSENSITIVE;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.SELECT_USER_CASE_INSENSITIVE;

public class JDBCUserStoreManager extends AbstractUserStoreManager {
    private static final Log log = LogFactory.getLog(JDBCUserStoreManager.class);
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    private static final String SHA_1_PRNG = "SHA1PRNG";
    private static final String DISPLAY_NAME_CLAIM = "http://wso2.org/claims/displayName";
    private static final String TRUE_VALUE = "true";
    private DataSource jdbcDataSource = null;

    public JDBCUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, Integer tenantId)
            throws UserStoreException {
        this(realmConfig, tenantId);
        logDebug("JDBCUserStoreManager initialization started at: " + System.currentTimeMillis());
        initializeDataSource(realmConfig, properties);
        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig.getUserStoreProperties()));
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()));
        }
        logDebug("JDBCUserStoreManager initialization ended at: " + System.currentTimeMillis());
    }

    private void initializeDataSource(RealmConfiguration realmConfig, Map<String, Object> properties) throws DashboardUserStoreException {
        try {
            jdbcDataSource = loadUserStoreSpecificDataSource();
            properties.put(UserStoreConstants.DATA_SOURCE, jdbcDataSource);
            logDebug("The jdbcDataSource being used by JDBCUserStoreManager :: " + jdbcDataSource.hashCode());
        } catch (Exception e) {
            log.error("Failed to load JDBC datasource", e);
        }
        dataSource = (DataSource) properties.get(UserStoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new DashboardUserStoreException("User Management Data Source is null");
        }
    }

    private DataSource loadUserStoreSpecificDataSource() {
        return DatabaseUtil.createUserStoreDataSource(realmConfig);
    }

    public JDBCUserStoreManager(RealmConfiguration realmConfig, int tenantId) {
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig.getUserStoreProperties()));
        initializeGroupSettings();
    }

    private void initializeGroupSettings() {
        writeGroupsEnabled = parseGroupSetting(WRITE_GROUPS_ENABLED, !isReadOnly());
        // If write groups are enabled, read groups auto enabled
        readGroupsEnabled = writeGroupsEnabled || parseGroupSetting(READ_GROUPS_ENABLED, false);
        logDebug("ReadGroups is " + (readGroupsEnabled ? "enabled" : "disabled"));
        logDebug("WriteGroups is " + (writeGroupsEnabled ? "enabled" : "disabled"));
    }

    private boolean parseGroupSetting(String propertyName, boolean defaultValue) {
        String propertyValue = realmConfig.getUserStoreProperty(propertyName);
        return propertyValue != null ? Boolean.parseBoolean(propertyValue) : defaultValue;
    }

    private static void logDebug(String message) {
        if (log.isDebugEnabled()) {
            log.debug(message);
        }
    }

    @Override
    protected boolean doAuthenticate(String username, Object credential) throws UserStoreException {
        if (!isValidUsername(username) || !isValidPasswordFormat(credential)) {
            logDebug("Username or password validation failed");
            return false;
        }

        Connection connection = null;
        ResultSet resultSet = null;
        PreparedStatement statement = null;
        try {
            connection = getDBConnection();
            connection.setAutoCommit(false);
            statement = createSelectUserPreparedStatement(connection, username);
            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return authenticateUser(resultSet, credential);
            }
            logDebug("User " + username + " login attempt. Login failed");
            return false;
        } catch (SQLException e) {
            String message = "Error occurred while retrieving user authentication info for user : " + username;
            logDebug(message, e);
            throw new DashboardUserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(connection, resultSet, statement);
        }
    }

    private boolean authenticateUser(ResultSet resultSet, Object credential) throws SQLException, UserStoreException {
        String storedPassword = resultSet.getString(3);
        String saltValue = getSaltValue(resultSet);
        boolean requireChange = resultSet.getBoolean(5);
        Timestamp changedTime = resultSet.getTimestamp(6);

        if (passwordChangeNotRequired(requireChange, changedTime)) {
            String preparedPassword = preparePassword(credential, saltValue);
            if (storedPassword != null && storedPassword.equals(preparedPassword)) {
                logDebug("Authentication successful");
                return true;
            }
        }
        return false;
    }

    private boolean passwordChangeNotRequired(boolean requireChange, Timestamp changedTime) {
        if (!requireChange) return true;

        GregorianCalendar gc = new GregorianCalendar();
        gc.add(GregorianCalendar.HOUR, -24);
        return !changedTime.before(gc.getTime());
    }

    private String getSaltValue(ResultSet resultSet) throws SQLException {
        return TRUE_VALUE.equalsIgnoreCase(realmConfig.getUserStoreProperty(STORE_SALTED_PASSWORDS))
                ? resultSet.getString(4) : null;
    }

    private String preparePassword(Object password, String salt) throws UserStoreException {
        try (Secret secret = Secret.getSecret(password)) {
            addSaltIfPresent(secret, salt);
            return getHashedOrPlainPassword(secret);
        } catch (UnsupportedSecretTypeException e) {
            throw new DashboardUserStoreException("Unsupported credential type", e);
        } catch (NoSuchAlgorithmException e) {
            String message = "Error occurred while preparing password.";
            logDebug(message, e);
            throw new DashboardUserStoreException(message, e);
        }
    }

    private void addSaltIfPresent(Secret secret, String saltValue) {
        if (saltValue != null) {
            secret.addChars(saltValue.toCharArray());
        }
    }

    private String getHashedOrPlainPassword(Secret secret) throws NoSuchAlgorithmException {
        String digestFunction = realmConfig.getUserStoreProperties().get(DIGEST_FUNCTION);
        if (digestFunction == null || UserCoreConstants.RealmConfig.PASSWORD_HASH_METHOD_PLAIN_TEXT.equals(digestFunction)) {
            return new String(secret.getChars());
        }

        MessageDigest digest = MessageDigest.getInstance(digestFunction);
        byte[] hashedBytes = digest.digest(secret.getBytes());
        return Base64.encode(hashedBytes);
    }

    private static void logDebug(String message, Throwable throwable) {
        if (log.isDebugEnabled()) {
            log.debug(message, throwable);
        }
    }

    private PreparedStatement createSelectUserPreparedStatement(@NotNull Connection connection, String username) throws SQLException {
        String sqlStatement = realmConfig.getUserStoreProperty(isCaseSensitiveUsername() ? SELECT_USER : SELECT_USER_CASE_INSENSITIVE);
        logDebug(sqlStatement);

        PreparedStatement statement = connection.prepareStatement(sqlStatement);
        statement.setString(1, username);
        if (sqlStatement.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            statement.setInt(2, tenantId);
        }
        return statement;
    }

    private boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

    @Override
    public String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        if (maxItemLimit == 0) {
            return new String[0];
        }

        int givenMax = getConfiguredMaxUserList();
        int searchTime = getConfiguredSearchTime();

        maxItemLimit = adjustMaxItemLimit(maxItemLimit, givenMax);
        filter = prepareFilter(filter);

        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet resultSet = null;

        try {
            connection = getDBConnection();
            statement = createSelectUserWithFilterPreparedStatement(connection, filter, maxItemLimit, searchTime);
            resultSet = statement.executeQuery();

            List<String> userList = extractUserList(resultSet);
            String[] users = userList.toArray(new String[0]);
            Arrays.sort(users);
            return users;
        } catch (SQLTimeoutException e) {
            log.error("Query timeout while fetching users. Ignoring error.", e);
            return new String[0];
        } catch (SQLException e) {
            String message = "Error occurred while retrieving users for filter : " + filter + " & max Item limit : " + maxItemLimit;
            logDebug(message, e);
            throw new DashboardUserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(connection, resultSet, statement);
        }
    }

    private List<String> extractUserList(ResultSet resultSet) throws SQLException {
        List<String> userList = new LinkedList<>();
        while (resultSet.next()) {
            String name = resultSet.getString(1);
            userList.add(name);
        }
        return userList;
    }

    private PreparedStatement createSelectUserWithFilterPreparedStatement(Connection connection, String filter,
                                                                          int maxItemLimit, int searchTime)
            throws SQLException, UserStoreException {
        if (connection == null) {
            throw new UserStoreException("Database connection is null");
        }

        String sqlStmt = realmConfig.getUserStoreProperty(isCaseSensitiveUsername() ? GET_USER_FILTER : GET_USER_FILTER_CASE_INSENSITIVE);
        PreparedStatement statement = connection.prepareStatement(sqlStmt);
        statement.setString(1, filter);
        if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            statement.setInt(2, tenantId);
        }
        statement.setMaxRows(maxItemLimit);
        try {
            statement.setQueryTimeout(searchTime);
        } catch (Exception e) {
            logDebug("Query timeout setting is not supported.", e);
        }
        return statement;
    }

    private int getConfiguredMaxUserList() {
        try {
            return Integer.parseInt(realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            return UserCoreConstants.MAX_USER_ROLE_LIST;
        }
    }

    private int getConfiguredSearchTime() {
        try {
            return Integer.parseInt(realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            return UserCoreConstants.MAX_SEARCH_TIME;
        }
    }

    private int adjustMaxItemLimit(int maxItemLimit, int givenMax) {
        return (maxItemLimit < 0 || maxItemLimit > givenMax) ? givenMax : maxItemLimit;
    }

    private String prepareFilter(String filter) {
        if (filter == null || filter.trim().isEmpty()) {
            return "%";
        }
        return filter.trim().replace("*", "%").replace("?", "_");
    }

    @Override
    protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {
        logDebug("Getting roles of user: " + userName + " with filter: " + filter);
        String sqlStmt;
        String[] names;
        if (filter.equals("*") || StringUtils.isEmpty(filter)) {
            sqlStmt = getExternalRoleListSqlStatement(
                    realmConfig.getUserStoreProperty(GET_USER_ROLE),
                    realmConfig.getUserStoreProperty(GET_USER_ROLE_CASE_INSENSITIVE));
            if (sqlStmt.contains(UserStoreConstants.UM_TENANT_COLUMN)) {
                names = getStringValuesFromDatabase(sqlStmt, userName, tenantId, tenantId, tenantId);
            } else {
                names = getStringValuesFromDatabase(sqlStmt, userName);
            }
        } else {
            filter = filter.trim();
            filter = filter.replace("*", "%");
            filter = filter.replace("?", "_");
            sqlStmt = getExternalRoleListSqlStatement(
                    realmConfig.getUserStoreProperty(GET_IS_USER_ROLE_EXIST), realmConfig
                            .getUserStoreProperty(
                                    GET_IS_USER_ROLE_EXIST_CASE_INSENSITIVE));

            if (sqlStmt.contains(UserStoreConstants.UM_TENANT_COLUMN)) {
                names = getStringValuesFromDatabase(sqlStmt, userName, tenantId, tenantId, tenantId, filter);
            } else {
                names = getStringValuesFromDatabase(sqlStmt, userName, filter);
            }
        }
        List<String> roles = new ArrayList<>();

        if (names == null) {
            names = new String[0];
            logDebug("No external role found for the user: " + userName);
        }


        Collections.addAll(roles, names);
        return roles.toArray(new String[0]);
    }

    private String getExternalRoleListSqlStatement(String caseSensitiveUsernameQuery,
                                                   String nonCaseSensitiveUsernameQuery)
            throws UserStoreException {
        String sqlStmt;
        if (isCaseSensitiveUsername()) {
            sqlStmt = caseSensitiveUsernameQuery;
        } else {
            sqlStmt = nonCaseSensitiveUsernameQuery;
        }
        if (sqlStmt == null) {
            throw new DashboardUserStoreException("The sql statement for retrieving user roles is null");
        }
        return sqlStmt;
    }

    @Override
    public String[] doGetUserListOfRole(String roleName) throws UserStoreException {
        RoleContext roleContext = createRoleContext(roleName);
        return getUserListOfJDBCRole(roleContext);
    }

    public String[] getUserListOfJDBCRole(RoleContext ctx) throws UserStoreException {

        String roleName = ctx.getRoleName();
        String[] names = null;
        String sqlStmt;
        if (!ctx.isShared()) {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_USERS_IN_ROLE);
            if (sqlStmt == null) {
                throw new UserStoreException("The sql statement for retrieving user roles is null");
            }
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                names =
                        getStringValuesFromDatabase(sqlStmt, roleName, tenantId, tenantId, tenantId);
            } else {
                names = getStringValuesFromDatabase(sqlStmt, roleName);
            }
        } else if (ctx.isShared()) {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_USERS_IN_SHARED_ROLE);
            names = getStringValuesFromDatabase(sqlStmt, roleName);
        }

        List<String> userList = new ArrayList<>();

        if (names != null) {
            Collections.addAll(userList, names);
            names = userList.toArray(new String[0]);
        }
        log.debug("Roles are not defined for the role name " + roleName);

        return names;
    }

    private String[] getStringValuesFromDatabase(String sqlStmt, Object... params) throws UserStoreException {
        logDebug("Executing Query: " + sqlStmt);
        for (Object param : params) {
            logDebug("Input value: " + param);
        }
        String[] values;
        Connection connection = null;
        try {
            connection = getDBConnection();
            values = DatabaseUtil.getStringValuesFromDatabase(connection, sqlStmt, params);
        } catch (SQLException e) {
            String message = "Error occurred while retrieving string values.";
            logDebug(message, e);
            throw new DashboardUserStoreException(message, e);
        } finally {
            DatabaseUtil.closeConnection(connection);
        }
        return values;
    }

    @Override
    public boolean doCheckExistingUser(String userName) throws UserStoreException {

        String sqlStmt;
        if (isCaseSensitiveUsername()) {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_IS_USER_EXISTING);
        } else {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.GET_IS_USER_EXISTING_CASE_INSENSITIVE);
        }
        if (sqlStmt == null) {
            throw new UserStoreException("The sql statement for is user existing null");
        }
        boolean isExisting;

        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if (Boolean.parseBoolean(isUnique) && !UserCoreConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
            String uniquenessSql;
            if (isCaseSensitiveUsername()) {
                uniquenessSql = realmConfig.getUserStoreProperty(JDBCRealmConstants.USER_NAME_UNIQUE);
            } else {
                uniquenessSql = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.USER_NAME_UNIQUE_CASE_INSENSITIVE);
            }
            isExisting = isValueExisting(uniquenessSql, userName);
            if (log.isDebugEnabled()) {
                log.debug("The username should be unique across tenants.");
            }
        } else {
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                isExisting = isValueExisting(sqlStmt, userName, tenantId);
            } else {
                isExisting = isValueExisting(sqlStmt, userName);
            }
        }

        return isExisting;
    }

    @Override
    public void doAddUser(String userName, Object credential, String[] roleList,
                          Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        String userID = UUID.randomUUID().toString();

        // persist the user info. in the database.
        persistUser(userID, userName, credential, roleList, claims, profileName, requirePasswordChange);

    }

    @Override
    public void doDeleteUser(String userName) throws UserStoreException {
        String sqlStmt1;
        if (isCaseSensitiveUsername()) {
            sqlStmt1 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ON_DELETE_USER_REMOVE_USER_ROLE);
        } else {
            sqlStmt1 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                    .ON_DELETE_USER_REMOVE_USER_ROLE_CASE_INSENSITIVE);
        }
        if (sqlStmt1 == null) {
            throw new UserStoreException("The sql statement for delete user-role mapping is null");
        }

        String sqlStmt2;
        if (isCaseSensitiveUsername()) {
            sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE);
        } else {
            sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                    .ON_DELETE_USER_REMOVE_ATTRIBUTE_CASE_INSENSITIVE);
        }
        if (sqlStmt2 == null) {
            throw new UserStoreException("The sql statement for delete user attribute is null");
        }

        String sqlStmt3;
        if (isCaseSensitiveUsername()) {
            sqlStmt3 = realmConfig.getUserStoreProperty(JDBCRealmConstants.DELETE_USER);
        } else {
            sqlStmt3 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.DELETE_USER_CASE_INSENSITIVE);
        }
        if (sqlStmt3 == null) {
            throw new UserStoreException("The sql statement for delete user is null");
        }

        Connection connection = null;
        try {
            connection = getDBConnection();
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(connection, sqlStmt1, userName, tenantId,
                        tenantId);
                this.updateStringValuesToDatabase(connection, sqlStmt2, userName, tenantId,
                        tenantId);
                this.updateStringValuesToDatabase(connection, sqlStmt3, userName, tenantId);
            } else {
                this.updateStringValuesToDatabase(connection, sqlStmt1, userName);
                this.updateStringValuesToDatabase(connection, sqlStmt2, userName);
                this.updateStringValuesToDatabase(connection, sqlStmt3, userName);
            }
            connection.commit();
        } catch (SQLException e) {
            String msg = "Error occurred while deleting user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            DatabaseUtil.closeAllConnections(connection);
        }
    }

    @Override
    public void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {

        Connection connection = null;
        try {
            connection = getDBConnection();
            String type = DatabaseCreator.getDatabaseType(connection);
            String sqlStmt2;
            if (deletedRoles != null && deletedRoles.length > 0) {
                // Break the provided role list based on whether roles are shared or not
                RoleBreakdown breakdown = getSharedRoleBreakdown(deletedRoles);
                String[] roles = breakdown.getRoles();
                // Integer[] tenantIds = breakdown.getTenantIds();

                String sqlStmt1;

                if (roles.length > 0) {
                    if (isCaseSensitiveUsername()) {
                        sqlStmt1 = realmConfig.getUserStoreProperty(JDBCRealmConstants.REMOVE_ROLE_FROM_USER);
                    } else {
                        sqlStmt1 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                                .REMOVE_ROLE_FROM_USER_CASE_INSENSITIVE);
                    }
                    if (sqlStmt1 == null) {
                        throw new UserStoreException(
                                "The sql statement for remove user from role is null");
                    }
                    if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt1,
                                roles, tenantId, userName,
                                tenantId, tenantId);
                    } else {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt1, roles, userName);
                    }
                }
            }

            if (newRoles != null && newRoles.length > 0) {

                ArrayList<String> newRoleList = new ArrayList<>();
                for (String role : newRoles) {
                    if (!isExistingRole(role)) {
                        String errorMessage = "The role: " + role + " does not exist.";
                        throw new UserStoreException(errorMessage);
                    }
                    if (!isUserInRole(userName, role)) {
                        newRoleList.add(role);
                    }
                }

                String[] rolesToAdd = newRoleList.toArray(new String[0]);
                // if username and role names are prefixed with domain name,
                // remove the domain name
                RoleBreakdown breakdown = getSharedRoleBreakdown(rolesToAdd);

                String[] roles = breakdown.getRoles();

                // Integer[] tenantIds = breakdown.getTenantIds();

                if (roles.length > 0) {

                    if (isCaseSensitiveUsername()) {
                        realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_ROLE_TO_USER + "-" + type);
                    } else {
                        realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.ADD_ROLE_TO_USER_CASE_INSENSITIVE + "-" +
                                type);
                    }
                    if (isCaseSensitiveUsername()) {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_ROLE_TO_USER);
                    } else {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                                .ADD_ROLE_TO_USER_CASE_INSENSITIVE);
                    }
                    if (sqlStmt2 == null) {
                        throw new UserStoreException(
                                "The sql statement for add user to role is null");
                    }
                    if (sqlStmt2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        if (UserCoreConstants.OPENEDGE_TYPE.equals(type)) {
                            DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2,
                                    tenantId, roles,
                                    tenantId, userName,
                                    tenantId);
                        } else {
                            DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2,
                                    roles, tenantId,
                                    userName, tenantId,
                                    tenantId);
                        }
                    } else {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2, newRoles, userName);
                    }
                }
            }
            connection.commit();
        } catch (SQLException e) {
            String msg = "Database error occurred while updating role list of user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } catch (UserStoreException e) {
            String errorMessage = "Error occurred while updating role list of user:" + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(e.getMessage(), e);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(connection);
        }

    }

    /**
     * Break the provided role list based on whether roles are shared or not
     */
    // TODO: check whether this function is needed since removed the shared role break down
    private RoleBreakdown getSharedRoleBreakdown(String[] rolesList) {
        List<String> roles = new ArrayList<>();
        List<Integer> tenantIds = new ArrayList<>();
        for (String role : rolesList) {
            if (StringUtils.isNotEmpty(role)) {
                JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(role);
                roles.add(ctx.getRoleName());
                tenantIds.add(ctx.getTenantId());
            }
        }
        RoleBreakdown breakdown = new RoleBreakdown();
        breakdown.setRoles(roles.toArray(new String[0]));
        breakdown.setTenantIds(tenantIds.toArray(new Integer[0]));
        return breakdown;
    }

    public void doDeleteRole(String roleName) throws UserStoreException {
        String sqlStmt1 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE);
        if (sqlStmt1 == null) {
            throw new UserStoreException("The sql statement for delete user-role mapping is null");
        }
        String sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.DELETE_ROLE);
        if (sqlStmt2 == null) {
            throw new UserStoreException("The sql statement for delete role is null");
        }
        Connection connection = null;
        try {
            connection = getDBConnection();
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(connection, sqlStmt1, roleName, tenantId, tenantId);
                this.updateStringValuesToDatabase(connection, sqlStmt2, roleName, tenantId);
            } else {
                this.updateStringValuesToDatabase(connection, sqlStmt1, roleName);
                this.updateStringValuesToDatabase(connection, sqlStmt2, roleName);
            }
            connection.commit();
        } catch (SQLException e) {
            String message = "Error occurred while deleting role : " + roleName;
            logDebug(message, e);
            throw new UserStoreException(message, e);
        } finally {
            DatabaseUtil.closeConnection(connection);
        }
    }

    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        String sqlStmt;
        if (isCaseSensitiveUsername()) {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.UPDATE_USER_PASSWORD);
        } else {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.UPDATE_USER_PASSWORD_CASE_INSENSITIVE);
        }
        if (sqlStmt == null) {
            throw new UserStoreException("The sql statement for delete user claim value is null");
        }
        String saltValue = null;
        if ("true".equalsIgnoreCase(realmConfig.getUserStoreProperties().get(
                JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
            saltValue = generateSaltValue();
        }

        String password = this.preparePassword(newCredential, saltValue);

        if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            updateStringValuesToDatabase(null, sqlStmt, password, "", false, new Date(), userName,
                    tenantId);
        } else if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue != null) {
            updateStringValuesToDatabase(null, sqlStmt, password, saltValue, false, new Date(),
                    userName, tenantId);
        } else if (!sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            updateStringValuesToDatabase(null, sqlStmt, password, "", false, new Date(), userName);
        } else {
            updateStringValuesToDatabase(null, sqlStmt, password, saltValue, false, new Date(),
                    userName);
        }
    }

    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential) throws UserStoreException {
        this.doUpdateCredentialByAdmin(userName, newCredential);
    }

    @Override
    public String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        String[] roles = new String[0];
        Connection connection = null;
        String sqlStmt;
        PreparedStatement statement;
        statement = null;
        ResultSet resultSet = null;

        if (maxItemLimit == 0) {
            return roles;
        }

        try {

            if (filter != null && !filter.trim().isEmpty()) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<>();

            connection = getDBConnection();

            if (connection == null) {
                throw new UserStoreException("null connection");
            }

            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_ROLE_LIST); // TODO

            statement = connection.prepareStatement(sqlStmt);
            //statement.setString(1, filter);
            byte count = 0;
            statement.setString(++count, filter);
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                statement.setInt(++count, tenantId);
            }
            setPSRestrictions(statement, maxItemLimit);
            try {
                resultSet = statement.executeQuery();
            } catch (SQLException e) {
                if (e instanceof SQLTimeoutException) {
                    log.error("The cause might be a time out. Hence ignored", e);
                } else {
                    String errorMessage =
                            "Error while fetching roles from JDBC user store according to filter : " + filter +
                                    " & max item limit : " + maxItemLimit;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }
                    throw new UserStoreException(errorMessage, e);
                }
            }

            //Expected columns UM_ROLE_NAME, UM_TENANT_ID, UM_SHARED_ROLE
            if (resultSet != null) {
                while (resultSet.next()) {
                    String name = resultSet.getString(1);
                    lst.add(name);
                }
            }
            if (!lst.isEmpty()) {
                roles = lst.toArray(new String[0]);
            }

        } catch (SQLException e) {
            String msg = "Error occurred while retrieving role names for filter : " + filter + " & max item limit : " +
                    maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            DatabaseUtil.closeAllConnections(connection, resultSet, statement);
        }
        return roles;

    }

    private void setPSRestrictions(PreparedStatement ps, int maxItemLimit) throws SQLException {

        int givenMax;

        int searchTime;

        try {
            givenMax = Integer.parseInt(realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_ROLE_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = UserCoreConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        ps.setMaxRows(maxItemLimit);
        try {
            ps.setQueryTimeout(searchTime);
        } catch (Exception e) {
            // this can be ignored since timeout method is not implemented
            log.debug(e);
        }
    }

    public boolean doCheckExistingRole(String roleName) throws UserStoreException {
        RoleContext roleContext = createRoleContext(roleName);  // TODO if role Name with Shared Role?
        return isExistingJDBCRole(roleContext);
    }

    @Override
    protected RoleContext createRoleContext(String roleName) {
        JDBCRoleContext searchCtx = new JDBCRoleContext();
        searchCtx.setTenantId(this.tenantId);
        searchCtx.setRoleName(roleName);
        return searchCtx;
    }

    @Override
    public void doAddRole(String roleName, String[] userList) throws UserStoreException {
        Connection connection = null;
        try {
            connection = getDBConnection();
            String sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_ROLE);
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(connection, sqlStmt, roleName, tenantId);
            } else {
                this.updateStringValuesToDatabase(connection, sqlStmt, roleName);
            }
            if (userList != null) {
                // add role to user
                String type = DatabaseCreator.getDatabaseType(connection);
                String sqlStmt2;
                if (isCaseSensitiveUsername()) {
                    sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_TO_ROLE + "-" + type);
                } else {
                    sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                            .ADD_USER_TO_ROLE_CASE_INSENSITIVE + "-" + type);
                }
                if (sqlStmt2 == null) {
                    if (isCaseSensitiveUsername()) {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_TO_ROLE);
                    } else {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                                .ADD_USER_TO_ROLE_CASE_INSENSITIVE);
                    }
                }
                if (sqlStmt2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    if (UserCoreConstants.OPENEDGE_TYPE.equals(type)) {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2,
                                tenantId, userList, tenantId, roleName, tenantId);
                    } else {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2,
                                userList, tenantId, roleName, tenantId, tenantId);
                    }
                } else {
                    DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2, userList, roleName);
                }

            }
            connection.commit();
        } catch (SQLException e) {
            String msg = "Error occurred while adding role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            if (e instanceof UserStoreException && UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_WRITING_TO_DATABASE.getCode().equals((
                    (UserStoreException) e).getErrorCode())) {
                // Duplicate entry
                throw new UserStoreException(errorMessage, UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_ADDING_ROLE.getCode(), e);
            } else {
                // Other SQL Exception
                throw new UserStoreException(errorMessage, e);
            }
        } finally {
            DatabaseUtil.closeAllConnections(connection);
        }
    }

    @Override
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {
        String[] roles = doGetExternalRoleListOfUser(userName, roleName);
        if (roles != null) {
            for (String role : roles) {
                if (role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public boolean isExistingUser(String s) {
        return false;
    }

    protected boolean isExistingJDBCRole(RoleContext context) throws UserStoreException {

        boolean isExisting;
        String roleName = context.getRoleName();

        String sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_IS_ROLE_EXISTING);
        if (sqlStmt == null) {
            throw new UserStoreException("The sql statement for is role existing role null");
        }

        if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            isExisting =
                    isValueExisting(sqlStmt, roleName, ((JDBCRoleContext) context).getTenantId());
        } else {
            isExisting = isValueExisting(sqlStmt, roleName);
        }

        return isExisting;
    }

    /**
     * This private method returns a saltValue using SecureRandom.
     *
     * @return saltValue
     */
    private String generateSaltValue() {
        String saltValue;
        try {
            SecureRandom secureRandom = SecureRandom.getInstance(SHA_1_PRNG);
            byte[] bytes = new byte[16];
            //secureRandom is automatically seeded by calling nextBytes
            secureRandom.nextBytes(bytes);
            saltValue = Base64.encode(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA1PRNG algorithm could not be found.");
        }
        return saltValue;
    }

    private void updateStringValuesToDatabase(Connection connection, String sqlStmt,
                                              Object... params) throws UserStoreException {
        PreparedStatement statement = null;
        boolean localConnection = false;
        try {
            if (connection == null) {
                localConnection = true;
                connection = getDBConnection();
            }
            statement = connection.prepareStatement(sqlStmt);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Invalid data provided");
                    } else if (param instanceof String) {
                        statement.setString(i + 1, (String) param);
                    } else if (param instanceof Integer) {
                        statement.setInt(i + 1, (Integer) param);
                    } else if (param instanceof Date) {
                        statement.setTimestamp(i + 1, new Timestamp(System.currentTimeMillis()));
                    } else if (param instanceof Boolean) {
                        statement.setBoolean(i + 1, (Boolean) param);
                    }
                }
            }
            int count = statement.executeUpdate();

            if (log.isDebugEnabled()) {
                if (count == 0) {
                    log.debug("No rows were updated");
                }
                log.debug("Executed query is " + sqlStmt + " and number of updated rows :: "
                        + count);
            }

            if (localConnection) {
                connection.commit();
            }
        } catch (SQLException e) {
            String msg = "Error occurred while updating string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            if (e instanceof SQLIntegrityConstraintViolationException) {
                // Duplicate entry
                throw new UserStoreException(msg, UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_WRITING_TO_DATABASE.getCode(), e);
            } else {
                // Other SQL Exception
                throw new UserStoreException(msg, e);
            }
        } finally {
            if (localConnection) {
                DatabaseUtil.closeAllConnections(connection);
            }
            DatabaseUtil.closeAllConnections(null, statement);
        }
    }

    protected boolean isValueExisting(String sqlStmt, Object... params) throws UserStoreException {
        boolean isExisting = false;
        Connection connection = null;
        try {
            connection = getDBConnection();
            if (DatabaseUtil.getIntegerValueFromDatabase(connection, sqlStmt, params) > -1) {
                isExisting = true;
            }
            return isExisting;
        } catch (SQLException e) {
            String message = "Error occurred while checking existence of values.";
            logDebug(message, e);
            throw new UserStoreException(message, e);
        } finally {
            DatabaseUtil.closeConnection(connection);
        }
    }

    protected Connection getDBConnection() throws SQLException {
        Connection connection = getJDBCDataSource().getConnection();
        connection.setAutoCommit(false);
        if (connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) {
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
        }
        return connection;
    }

    private DataSource getJDBCDataSource() {
        if (jdbcDataSource == null) {
            jdbcDataSource = loadUserStoreSpecificDataSource();
        }
        return jdbcDataSource;
    }

    @Override
    public String[] getProfileNames(String s) {
        return new String[0];
    }

    @Override
    public String getUserClaimValue(String s, String s1, String s2) {
        return "";
    }

    @Override
    public Map<String, String> getUserClaimValues(String s, String[] strings, String s1) {
        return Map.of();
    }

    @Override
    public Claim[] getUserClaimValues(String s, String s1) {
        return new Claim[0];
    }

    @Override
    public String[] getAllProfileNames() {
        return new String[0];
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public void addUser(String s, Object o, String[] strings, Map<String, String> map, String s1) {

    }

    @Override
    public void updateUserListOfRole(String s, String[] strings, String[] strings1) {

    }

    @Override
    public void setUserClaimValue(String s, String s1, String s2, String s3) {

    }

    @Override
    public void setUserClaimValues(String s, Map<String, String> map, String s1) {

    }

    @Override
    public void deleteUserClaimValue(String s, String s1, String s2) {

    }

    @Override
    public void deleteUserClaimValues(String s, String[] strings, String s1) {

    }

    @Override
    public String[] getAllSecondaryRoles() {
        return new String[0];
    }

    @Override
    public Date getPasswordExpirationTime(String s) {
        return null;
    }

    @Override
    public int getUserId(String s) throws UserStoreException {
        return 0;
    }

    @Override
    public int getTenantId(String s) {
        return 0;
    }

    public int getTenantId() {
        return this.tenantId;
    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateRoleName(String s, String s1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isBulkImportSupported() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getUserList(String s, String s1, String s2) {
        throw new UnsupportedOperationException();
    }

    @Override
    public UserStoreManager getSecondaryUserStoreManager() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setSecondaryUserStoreManager(UserStoreManager userStoreManager) {
        throw new UnsupportedOperationException();
    }

    @Override
    public UserStoreManager getSecondaryUserStoreManager(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addSecondaryUserStoreManager(String s, UserStoreManager userStoreManager) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return realmConfig;
    }

    @Override
    public boolean isExistingRole(String s, boolean b) {
        return false;
    }

    @Override
    public void addRole(String s, String[] strings, Permission[] permissions) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, String> getProperties(org.wso2.micro.integrator.security.user.api.Tenant tenant) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addRememberMe(String s, String s1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isValidRememberMeToken(String s, String s1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ClaimManager getClaimManager() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isSCIMEnabled() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Properties getDefaultUserStoreProperties() {
        throw new UnsupportedOperationException();
    }

    /*
     * This method persists the user information in the database.
     */
    protected void persistUser(String userID, String userName, Object credential, String[] roleList,
                               Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        Connection connection;
        try {
            connection = getDBConnection();
        } catch (SQLException e) {
            String errorMessage = "Error occurred while getting DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        try {
            String sqlStmt1 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_WITH_ID);

            String saltValue = null;

            if ("true".equalsIgnoreCase(realmConfig.getUserStoreProperties()
                    .get(JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
                saltValue = generateSaltValue();
            }

            String password = this.preparePassword(credentialObj, saltValue);

            // do all 4 possibilities
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue == null)) {
                this.updateStringValuesToDatabase(connection, sqlStmt1, userID, userName, password, "",
                        requirePasswordChange, new Date(), tenantId);
            } else if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue != null)) {
                this.updateStringValuesToDatabase(connection, sqlStmt1, userID, userName, password,
                        saltValue, requirePasswordChange, new Date(),
                        tenantId);
            } else if (!sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) &&
                    (saltValue == null)) {
                this.updateStringValuesToDatabase(connection, sqlStmt1, userID, userName, password, "",
                        requirePasswordChange, new Date());
            } else {
                this.updateStringValuesToDatabase(connection, sqlStmt1, userID, userName, password, saltValue,
                        requirePasswordChange, new Date());
            }

            if (roleList != null && roleList.length > 0) {

                RoleBreakdown breakdown = getSharedRoleBreakdown(roleList);
                String[] roles = breakdown.getRoles();

                String sqlStmt2;
                String type = DatabaseCreator.getDatabaseType(connection);
                if (roles.length > 0) {
                    // Adding user to the non-shared roles
                    if (isCaseSensitiveUsername()) {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_ROLE_TO_USER + "-" + type);
                    } else {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                                .ADD_ROLE_TO_USER_CASE_INSENSITIVE + "-" + type);
                    }
                    if (sqlStmt2 == null) {
                        if (isCaseSensitiveUsername()) {
                            sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_ROLE_TO_USER);
                        } else {
                            sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                                    .ADD_ROLE_TO_USER_CASE_INSENSITIVE);
                        }
                    }

                    if (sqlStmt2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        if (UserCoreConstants.OPENEDGE_TYPE.equals(type)) {
                            DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2,
                                    tenantId, roles,
                                    tenantId, userName,
                                    tenantId);
                        } else {
                            DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2,
                                    roles, tenantId,
                                    userName, tenantId,
                                    tenantId);
                        }
                    } else {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(connection, sqlStmt2, roleList, userName);
                    }

                }
            }

            if (claims != null) {
                // add the properties
                if (profileName == null) {
                    profileName = UserCoreConstants.DEFAULT_PROFILE;
                }

                addProperties(connection, userName, claims, profileName);
            }

            connection.commit();
        } catch (Exception e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                String errorMessage = "Error rollback add user operation for user : " + userName;
                logDebug(errorMessage, e1);
                throw new UserStoreException(errorMessage, e1);
            }
            String errorMessage = "Error while persisting user : " + userName;
            logDebug(errorMessage, e);

            if (e instanceof UserStoreException && UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_WRITING_TO_DATABASE.getCode().equals((
                    (UserStoreException) e).getErrorCode())) {
                // Duplicate entry
                throw new UserStoreException(errorMessage, UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_ADDING_A_USER.getCode(), e);
            } else {
                // Other SQL Exception
                throw new UserStoreException(errorMessage, e);
            }
        } finally {
            credentialObj.clear();
            DatabaseUtil.closeAllConnections(connection);
        }
    }

    private void addProperties(@NotNull Connection connection, String userName, Map<String, String> properties,
                               String profileName) throws UserStoreException {
        String databaseType;
        try {
            databaseType = DatabaseCreator.getDatabaseType(connection);
        } catch (Exception e) {
            String message = "Error occurred while adding user properties for user : " + userName;
            logDebug(message, e);
            throw new UserStoreException(message, e);
        }

        String sqlStmt = getAddUserPropertySqlStatement(databaseType);
        PreparedStatement statement = null;

        try {
            statement = connection.prepareStatement(sqlStmt);

            Map<String, String> userAttributes = new HashMap<>();
            for (Map.Entry<String, String> entry : properties.entrySet()) {
                String attributeName = getClaimAttribute(entry.getKey());
                String attributeValue = entry.getValue();
                userAttributes.put(attributeName, attributeValue);
            }

            for (Map.Entry<String, String> entry : userAttributes.entrySet()) {
                String propertyName = entry.getKey();
                String propertyValue = entry.getValue();
                if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    if (UserCoreConstants.OPENEDGE_TYPE.equals(databaseType)) {
                        batchUpdateStringValuesToDatabase(statement, propertyName, propertyValue, profileName,
                                tenantId, userName, tenantId);
                    } else {
                        batchUpdateStringValuesToDatabase(statement, userName, tenantId, propertyName, propertyValue,
                                profileName, tenantId);
                    }
                } else {
                    batchUpdateStringValuesToDatabase(statement, userName, propertyName, propertyValue, profileName);
                }
            }

            int[] counts = statement.executeBatch();
            if (log.isDebugEnabled()) {
                int totalUpdated = 0;
                if (counts != null) {
                    for (int i : counts) {
                        totalUpdated += i;
                    }
                }

                if (totalUpdated == 0) {
                    logDebug("No rows were updated");
                }
                logDebug("Executed query is " + sqlStmt + " and number of updated rows :: " + totalUpdated);
            }
        } catch (SQLException e) {
            String message = "Error occurred while updating string values to database.";
            logDebug(message, e);
            throw new UserStoreException(message, e);
        } finally {
            DatabaseUtil.closeAllConnections(null, statement);
        }
    }

    private String getAddUserPropertySqlStatement(String databaseType) throws UserStoreException {
        String sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_PROPERTY + "-" + databaseType);
        if (sqlStmt == null) {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_PROPERTY);
        }
        if (sqlStmt == null) {
            throw new UserStoreException("The sql statement for add user property sql is null");
        }
        return sqlStmt;
    }

    protected String getClaimAttribute(String claimURI) throws UserStoreException {
        try {
            String attributeName = claimManager.getAttributeName(claimURI);
            if (attributeName != null) {
                return attributeName;
            }
        } catch (org.wso2.micro.integrator.security.user.api.UserStoreException e) {
            throw new UserStoreException(e.getMessage(), e);
        }
        switch (claimURI) {
            case UserCoreConstants.PROFILE_CONFIGURATION:
                return claimURI;
            case DISPLAY_NAME_CLAIM:
                return realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
            default:
                throw new UserStoreException("Mapped attribute cannot be found for claim: " + claimURI + " in user store.");
        }
    }

    private void batchUpdateStringValuesToDatabase(PreparedStatement statement, Object... params) throws UserStoreException {
        if (params == null || params.length == 0) {
            throw new UserStoreException("No parameters provided for batch update.");
        }
        try {
            for (int i = 0; i < params.length; i++) {
                setPreparedStatementParameter(statement, i + 1, params[i]);
            }
            statement.addBatch();
        } catch (SQLException e) {
            String message = "Error occurred while updating property values to database.";
            logDebug(message, e);
            throw new UserStoreException(message, e);
        }
    }

    private void setPreparedStatementParameter(PreparedStatement statement, int index, Object param)
            throws SQLException, UserStoreException {
        if (param == null) {
            throw new UserStoreException("Invalid data provided at parameter index: " + index);
        }
        if (param instanceof String) {
            statement.setString(index, (String) param);
        } else if (param instanceof Integer) {
            statement.setInt(index, (Integer) param);
        } else if (param instanceof Date) {
            statement.setTimestamp(index, new Timestamp(((Date) param).getTime()));
        } else if (param instanceof Boolean) {
            statement.setBoolean(index, (Boolean) param);
        } else {
            throw new UserStoreException("Unsupported parameter type at index " + index + ": " + param.getClass().getSimpleName());
        }
    }
}

