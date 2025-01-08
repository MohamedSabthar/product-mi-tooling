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
import org.wso2.dashboard.security.user.core.*;
import org.wso2.dashboard.security.user.core.common.AbstractUserStoreManager;
import org.wso2.dashboard.security.user.core.common.DashboardUserStoreException;
import org.wso2.dashboard.security.user.core.common.Secret;
import org.wso2.dashboard.security.user.core.common.UnsupportedSecretTypeException;
import org.wso2.micro.integrator.security.user.api.Permission;
import org.wso2.micro.integrator.security.user.api.Properties;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserRealm;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.claim.Claim;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.tenant.Tenant;
import org.wso2.micro.integrator.security.user.core.util.JDBCRealmUtil;
import org.wso2.micro.integrator.security.user.core.UserStoreManager;

import javax.sql.DataSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.READ_GROUPS_ENABLED;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.WRITE_GROUPS_ENABLED;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.*;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.SELECT_USER;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.*;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.SELECT_USER_CASE_INSENSITIVE;

public class JDBCUserStoreManager extends AbstractUserStoreManager {
    private static final Log log = LogFactory.getLog(JDBCUserStoreManager.class);
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    protected DataSource jdbcds = null;

    public JDBCUserStoreManager() {
    }

    public JDBCUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                ClaimManager claimManager, UserRealm realm, Integer tenantId)
            throws DashboardUserStoreException {
        this(realmConfig, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.claimManager = claimManager;
        this.userRealm = realm;

        try {
            jdbcds = loadUserStoreSpecificDataSource();
            properties.put(UserStoreConstants.DATA_SOURCE, jdbcds);

            if (log.isDebugEnabled()) {
                log.debug("The jdbcDataSource being used by JDBCUserStoreManager :: " + jdbcds.hashCode());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Loading JDBC datasource failed", e);
            }
        }

        dataSource = (DataSource) properties.get(UserStoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new DashboardUserStoreException("User Management Data Source is null");
        }

        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig
                .getUserStoreProperties()));

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
    }

    public JDBCUserStoreManager(RealmConfiguration realmConfig, int tenantId) {
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig.getUserStoreProperties()));
        if (realmConfig.getUserStoreProperty(READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig.getUserStoreProperty(READ_GROUPS_ENABLED));
        }

        if (log.isDebugEnabled()) {
            String status = readGroupsEnabled ? "enabled" : "disabled";
            log.debug("ReadGroups is" + status + " for" + getMyDomainName());
        }

        if (realmConfig.getUserStoreProperty(WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig.getUserStoreProperty(WRITE_GROUPS_ENABLED));
        } else if (!isReadOnly()) {
            writeGroupsEnabled = true;
        }

        if (log.isDebugEnabled()) {
            String status = writeGroupsEnabled ? "enabled" : "disabled";
            log.debug("WriteGroups is" + status + " for" + getMyDomainName());
        }
        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }
    }

    private DataSource loadUserStoreSpecificDataSource() {
        return DatabaseUtil.createUserStoreDataSource(realmConfig);
    }

    @Override
    protected boolean doAuthenticate(String userName, Object credential) throws DashboardUserStoreException {
        if (!checkUserNameValid(userName)) {
            if (log.isDebugEnabled()) {
                log.debug("Username validation failed");
            }
            return false;
        }

        if (!checkUserPasswordValid(credential)) {
            if (log.isDebugEnabled()) {
                log.debug("Password validation failed");
            }
            return false;
        }

        if (UserStoreConstants.REGISTRY_SYSTEM_USERNAME.equals(userName)) {
            log.error("Anonymous user trying to login");
            return false;
        }

        Connection dbConnection = null;
        ResultSet rs = null;
        PreparedStatement prepStmt = null;
        boolean isAuthed = false;
        try {
            dbConnection = getDBConnection();
            dbConnection.setAutoCommit(false);
            String sqlStatement = realmConfig.getUserStoreProperty(isCaseSensitiveUsername()
                    ? SELECT_USER : SELECT_USER_CASE_INSENSITIVE);

            if (log.isDebugEnabled()) {
                log.debug(sqlStatement);
            }

            prepStmt = dbConnection.prepareStatement(sqlStatement);
            prepStmt.setString(1, userName);
            if (sqlStatement.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(2, tenantId);
            }

            rs = prepStmt.executeQuery();
            if (rs.next()) {
                String storedPassword = rs.getString(3);
                String saltValue = null;
                if ("true".equalsIgnoreCase(realmConfig
                        .getUserStoreProperty(STORE_SALTED_PASSWORDS))) {
                    saltValue = rs.getString(4);
                }

                boolean requireChange = rs.getBoolean(5);
                Timestamp changedTime = rs.getTimestamp(6);

                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();
                if (!requireChange || !changedTime.before(date)) {
                    String password = this.preparePassword(credential, saltValue);
                    if ((storedPassword != null) && (storedPassword.equals(password))) {
                        isAuthed = true;
                    }
                }
            }
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving user authentication info for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new DashboardUserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }

        if (log.isDebugEnabled()) {
            log.debug("User " + userName + " login attempt. Login success :: " + isAuthed);
        }
        return isAuthed;
    }

    public String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        String[] users = new String[0];
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;

        if (maxItemLimit == 0) {
            return new String[0];
        }

        int givenMax;
        int searchTime;

        try {
            givenMax = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        }

        try {
            searchTime = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = UserCoreConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
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

            dbConnection = getDBConnection();

            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }

            String sqlStmt = realmConfig.getUserStoreProperty(isCaseSensitiveUsername() ?
                    GET_USER_FILTER : GET_USER_FILTER_CASE_INSENSITIVE);


            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, filter);
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(2, tenantId);
            }
            prepStmt.setMaxRows(maxItemLimit);
            try {
                prepStmt.setQueryTimeout(searchTime);
            } catch (Exception e) {
                // this can be ignored since timeout method is not implemented
                log.debug(e);
            }

            try {
                rs = prepStmt.executeQuery();
            } catch (SQLException e) {
                if (e instanceof SQLTimeoutException) {
                    log.error("The cause might be a time out. Hence ignored", e);
                    return users;
                }
                String errorMessage =
                        "Error while fetching users according to filter : " + filter + " & max Item limit " +
                                ": " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }

            while (rs.next()) {

                String name = rs.getString(1);
                if (UserCoreConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(name)) {
                    continue;
                }
                lst.add(name);
            }
            rs.close();

            if (!lst.isEmpty()) {
                users = lst.toArray(new String[0]);
            }

            Arrays.sort(users);

        } catch (SQLException e) {
            String msg = "Error occurred while retrieving users for filter : " + filter + " & max Item limit : " +
                    maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);

        }
        return users;

    }

    private String[] getStringValuesFromDatabase(String sqlStmt, Object... params)
            throws DashboardUserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + sqlStmt);
            for (int i = 0; i < params.length; i++) {
                Object param = params[i];
                log.debug("Input value: " + param);
            }
        }

        String[] values;
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        try {
            dbConnection = getDBConnection();
            values = DatabaseUtil.getStringValuesFromDatabase(dbConnection, sqlStmt, params);
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving string values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new DashboardUserStoreException(msg, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }
        return values;
    }

    /**
     * Get the SQL statement for ExternalRoles.
     *
     * @param caseSensitiveUsernameQuery    query for getting role with case sensitive username.
     * @param nonCaseSensitiveUsernameQuery query for getting role with non-case sensitive username.
     * @return sql statement.
     * @throws UserStoreException
     */
    private String getExternalRoleListSqlStatement(String caseSensitiveUsernameQuery,
                                                   String nonCaseSensitiveUsernameQuery)
            throws DashboardUserStoreException {
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

    private String preparePassword(Object password, String saltValue) throws DashboardUserStoreException {
        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(password);
        } catch (UnsupportedSecretTypeException e) {
            throw new DashboardUserStoreException("Unsupported credential type", e);
        }
        try {
            String passwordString;
            if (saltValue != null) {
                credentialObj.addChars(saltValue.toCharArray());
            }

            String digestFunction = realmConfig.getUserStoreProperties().get(DIGEST_FUNCTION);
            if (digestFunction != null) {
                if (digestFunction.equals(UserCoreConstants.RealmConfig.PASSWORD_HASH_METHOD_PLAIN_TEXT)) {
                    passwordString = new String(credentialObj.getChars());
                    return passwordString;
                }

                MessageDigest digest = MessageDigest.getInstance(digestFunction);
                byte[] byteValue = digest.digest(credentialObj.getBytes());
                passwordString = Base64.encode(byteValue);
            } else {
                passwordString = new String(credentialObj.getChars());
            }

            return passwordString;
        } catch (NoSuchAlgorithmException e) {
            String msg = "Error occurred while preparing password.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new DashboardUserStoreException(msg, e);
        } finally {
            credentialObj.clear();
        }
    }

    private boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

    protected Connection getDBConnection() throws SQLException {
        Connection dbConnection = getJDBCDataSource().getConnection();
        dbConnection.setAutoCommit(false);
        if (dbConnection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) {
            dbConnection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
        }
        return dbConnection;
    }

    private DataSource getJDBCDataSource() {
        if (jdbcds == null) {
            jdbcds = loadUserStoreSpecificDataSource();
        }
        return jdbcds;
    }

    @Override
    public boolean isExistingUser(String s) throws UserStoreException {
        return false;
    }

    @Override
    public boolean isExistingRole(String s, boolean b) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        return false;
    }

    @Override
    public boolean isExistingRole(String s) throws UserStoreException {
        return false;
    }

    @Override
    public String[] getRoleNames() throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getRoleNames(boolean b) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getProfileNames(String s) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getUserListOfRole(String s) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String getUserClaimValue(String s, String s1, String s2) throws UserStoreException {
        return "";
    }

    @Override
    public Map<String, String> getUserClaimValues(String s, String[] strings, String s1) throws UserStoreException {
        return Map.of();
    }

    @Override
    public Claim[] getUserClaimValues(String s, String s1) throws UserStoreException {
        return new Claim[0];
    }

    @Override
    public String[] getAllProfileNames() throws UserStoreException {
        return new String[0];
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public void addUser(String s, Object o, String[] strings, Map<String, String> map, String s1) throws UserStoreException {

    }

    @Override
    public void addUser(String s, Object o, String[] strings, Map<String, String> map, String s1, boolean b) throws UserStoreException {

    }

    @Override
    public void updateCredential(String s, Object o, Object o1) throws UserStoreException {

    }

    @Override
    public void updateCredentialByAdmin(String s, Object o) throws UserStoreException {

    }

    @Override
    public void deleteUser(String s) throws UserStoreException {

    }

    @Override
    public void deleteRole(String s) throws UserStoreException {

    }

    @Override
    public void updateUserListOfRole(String s, String[] strings, String[] strings1) throws UserStoreException {

    }

    @Override
    public void updateRoleListOfUser(String s, String[] strings, String[] strings1) throws UserStoreException {

    }

    @Override
    public void setUserClaimValue(String s, String s1, String s2, String s3) throws UserStoreException {

    }

    @Override
    public void setUserClaimValues(String s, Map<String, String> map, String s1) throws UserStoreException {

    }

    @Override
    public void deleteUserClaimValue(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void deleteUserClaimValues(String s, String[] strings, String s1) throws UserStoreException {

    }

    @Override
    public String[] getHybridRoles() throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getAllSecondaryRoles() throws UserStoreException {
        return new String[0];
    }

    @Override
    public Date getPasswordExpirationTime(String s) throws UserStoreException {
        return null;
    }

    @Override
    public int getUserId(String s) throws UserStoreException {
        return 0;
    }

    @Override
    public int getTenantId(String s) throws UserStoreException {
        return 0;
    }

    public int getTenantId() {
        return this.tenantId;
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return null;
    }

    @Override
    protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws DashboardUserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Getting roles of user: " + userName + " with filter: " + filter);
        }
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
        List<String> roles = new ArrayList<String>();
        if (log.isDebugEnabled()) {
            if (names != null) {
                for (String name : names) {
                    log.debug("Found role: " + name);
                }
            } else {
                log.debug("No external role found for the user: " + userName);
            }
        }

        Collections.addAll(roles, names);
        return roles.toArray(new String[0]);
    }

    @Override
    protected String[] doGetSharedRoleListOfUser(String s, String s1, String s2) {
        return new String[0];
    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateRoleName(String s, String s1) throws UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Properties getDefaultUserStoreProperties() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isBulkImportSupported() throws UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getUserList(String s, String s1, String s2) throws UserStoreException {
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
    public void addRememberMe(String s, String s1) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isValidRememberMeToken(String s, String s1) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public org.wso2.micro.integrator.security.user.api.ClaimManager getClaimManager() throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isSCIMEnabled() throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();
    }


    @Override
    public void addRole(String s, String[] strings, Permission[] permissions, boolean b) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();

    }

    @Override
    public void addRole(String s, String[] strings, Permission[] permissions) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, String> getProperties(org.wso2.micro.integrator.security.user.api.Tenant tenant) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        throw new UnsupportedOperationException();
    }
}

