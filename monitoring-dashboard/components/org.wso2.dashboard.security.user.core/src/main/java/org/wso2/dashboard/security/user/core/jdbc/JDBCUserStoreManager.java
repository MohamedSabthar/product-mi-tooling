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
import org.wso2.dashboard.security.user.core.common.*;
import org.wso2.micro.core.util.DatabaseCreator;
import org.wso2.micro.integrator.security.user.api.Permission;
import org.wso2.micro.integrator.security.user.api.Properties;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.*;
import org.wso2.micro.integrator.security.user.core.claim.Claim;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants;
import org.wso2.micro.integrator.security.user.core.jdbc.JDBCRoleContext;
import org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants;
import org.wso2.micro.integrator.security.user.core.ldap.LDAPConstants;
import org.wso2.micro.integrator.security.user.core.tenant.Tenant;
import org.wso2.micro.integrator.security.user.core.util.JDBCRealmUtil;

import javax.sql.DataSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.Date;

import static org.apache.axis2.clustering.ClusteringConstants.Parameters.APPLICATION_DOMAIN;
import static org.wso2.carbon.user.core.UserCoreConstants.WORKFLOW_DOMAIN;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.READ_GROUPS_ENABLED;
import static org.wso2.dashboard.security.user.core.UserStoreConstants.RealmConfig.WRITE_GROUPS_ENABLED;
import static org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_ADDING_A_USER;
import static org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_DUPLICATE_WHILE_WRITING_TO_DATABASE;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.*;
import static org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants.SELECT_USER;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.*;
import static org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants.SELECT_USER_CASE_INSENSITIVE;

public class JDBCUserStoreManager extends AbstractUserStoreManager {
    private static final Log log = LogFactory.getLog(JDBCUserStoreManager.class);
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    private static final String SHA_1_PRNG = "SHA1PRNG";
    protected DataSource jdbcds = null;
    private static final String DISAPLAY_NAME_CLAIM = "http://wso2.org/claims/displayName";

    public JDBCUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                ClaimManager claimManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
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
    protected boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
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
            throw new DashboardUserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);

        }
        return users;

    }

    private String[] getStringValuesFromDatabase(String sqlStmt, Object... params)
            throws UserStoreException {

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

    private String preparePassword(Object password, String saltValue) throws UserStoreException {
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
    public void updateCredential(String s, Object o, Object o1) throws UserStoreException {

    }

    @Override
    public void updateCredentialByAdmin(String s, Object o) throws UserStoreException {

    }

    /**
     *
     */
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

        Connection dbConnection = null;
        try {
            dbConnection = getDBConnection();
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName, tenantId,
                        tenantId);
                this.updateStringValuesToDatabase(dbConnection, sqlStmt2, userName, tenantId,
                        tenantId);
                this.updateStringValuesToDatabase(dbConnection, sqlStmt3, userName, tenantId);
            } else {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName);
                this.updateStringValuesToDatabase(dbConnection, sqlStmt2, userName);
                this.updateStringValuesToDatabase(dbConnection, sqlStmt3, userName);
            }
            dbConnection.commit();
        } catch (SQLException e) {
            String msg = "Error occurred while deleting user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection);
        }
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
    protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {
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

    /**
     *
     */
    public void doAddUser(String userName, Object credential, String[] roleList,
                          Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        String userID = UUID.randomUUID().toString();

        // persist the user info. in the database.
        persistUser(userID, userName, credential, roleList, claims, profileName, requirePasswordChange);

    }



    /**
     * This private method returns a saltValue using SecureRandom.
     *
     * @return saltValue
     */
    private String generateSaltValue() {
        String saltValue = null;
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

    /**
     * @param dbConnection
     * @param sqlStmt
     * @param params
     * @throws UserStoreException
     */
    private void updateStringValuesToDatabase(Connection dbConnection, String sqlStmt,
                                              Object... params) throws UserStoreException {
        PreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            if (dbConnection == null) {
                localConnection = true;
                dbConnection = getDBConnection();
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Invalid data provided");
                    } else if (param instanceof String) {
                        prepStmt.setString(i + 1, (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(i + 1, (Integer) param);
                    } else if (param instanceof Date) {
                        // Timestamp timestamp = new Timestamp(((Date) param).getTime());
                        // prepStmt.setTimestamp(i + 1, timestamp);
                        prepStmt.setTimestamp(i + 1, new Timestamp(System.currentTimeMillis()));
                    } else if (param instanceof Boolean) {
                        prepStmt.setBoolean(i + 1, (Boolean) param);
                    }
                }
            }
            int count = prepStmt.executeUpdate();

            if (log.isDebugEnabled()) {
                if (count == 0) {
                    log.debug("No rows were updated");
                }
                log.debug("Executed query is " + sqlStmt + " and number of updated rows :: "
                        + count);
            }

            if (localConnection) {
                dbConnection.commit();
            }
        } catch (SQLException e) {
            String msg = "Error occurred while updating string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            if (e instanceof SQLIntegrityConstraintViolationException) {
                // Duplicate entry
                throw new UserStoreException(msg, ERROR_CODE_DUPLICATE_WHILE_WRITING_TO_DATABASE.getCode(), e);
            } else {
                // Other SQL Exception
                throw new UserStoreException(msg, e);
            }
        } finally {
            if (localConnection) {
                DatabaseUtil.closeAllConnections(dbConnection);
            }
            DatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }


    /*
     * This method persists the user information in the database.
     */
    protected void persistUser(String userID, String userName, Object credential, String[] roleList,
                               Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        Connection dbConnection = null;
        try{
            dbConnection = getDBConnection();
        }catch (SQLException e){
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
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userID, userName, password, "",
                        requirePasswordChange, new Date(), tenantId);
            } else if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue != null)) {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userID, userName, password,
                        saltValue, requirePasswordChange, new Date(),
                        tenantId);
            } else if (!sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) &&
                    (saltValue == null)) {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userID, userName, password, "",
                        requirePasswordChange, new Date());
            } else {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userID, userName, password, saltValue,
                        requirePasswordChange, new Date());
            }

            if (roleList != null && roleList.length > 0) {

                RoleBreakdown breakdown = getSharedRoleBreakdown(roleList);
                String[] roles = breakdown.getRoles();
                // Integer[] tenantIds = breakdown.getTenantIds();

                String[] sharedRoles = breakdown.getSharedRoles();
                Integer[] sharedTenantIds = breakdown.getTenantIds();

                String sqlStmt2 = null;
                String type = DatabaseCreator.getDatabaseType(dbConnection);
                if (roles.length > 0) {
                    // Adding user to the non shared roles
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
                            DatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt2,
                                    tenantId, roles,
                                    tenantId, userName,
                                    tenantId);
                        } else {
                            DatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt2,
                                    roles, tenantId,
                                    userName, tenantId,
                                    tenantId);
                        }
                    } else {
                        DatabaseUtil.udpateUserRoleMappingInBatchMode(dbConnection, sqlStmt2, roleList, userName);
                    }

                }
                if (sharedRoles.length > 0) {
                    // Adding user to the shared roles
                    if (isCaseSensitiveUsername()) {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_SHARED_ROLE_TO_USER);
                    } else {
                        sqlStmt2 = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants
                                .ADD_SHARED_ROLE_TO_USER_CASE_INSENSITIVE);
                    }
                    DatabaseUtil.udpateUserRoleMappingWithExactParams(dbConnection, sqlStmt2,
                            sharedRoles, userName,
                            sharedTenantIds, tenantId);
                }

            }

            if (claims != null) {
                // add the properties
                if (profileName == null) {
                    profileName = UserCoreConstants.DEFAULT_PROFILE;
                }

                addProperties(dbConnection, userName, claims, profileName);
            }

            dbConnection.commit();
        } catch (Exception e) {
            try {
                dbConnection.rollback();
            } catch (SQLException e1) {
                String errorMessage = "Error rollbacking add user operation for user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e1);
                }
                throw new UserStoreException(errorMessage, e1);
            }
            String errorMessage = "Error while persisting user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            if (e instanceof UserStoreException && ERROR_CODE_DUPLICATE_WHILE_WRITING_TO_DATABASE.getCode().equals((
                    (UserStoreException) e).getErrorCode())) {
                // Duplicate entry
                throw new UserStoreException(errorMessage, ERROR_CODE_DUPLICATE_WHILE_ADDING_A_USER.getCode(), e);
            } else {
                // Other SQL Exception
                throw new UserStoreException(errorMessage, e);
            }
        } finally {
            credentialObj.clear();
            DatabaseUtil.closeAllConnections(dbConnection);
        }
    }

    /**
     * Break the provided role list based on whether roles are shared or not
     *
     * @param rolesList
     * @return
     */
    private RoleBreakdown getSharedRoleBreakdown(String[] rolesList) {
        List<String> roles = new ArrayList<String>();
        List<Integer> tenantIds = new ArrayList<Integer>();

        List<String> sharedRoles = new ArrayList<String>();
        List<Integer> sharedTenantIds = new ArrayList<Integer>();

        for (String role : rolesList) {

            if (StringUtils.isNotEmpty(role)) {
//                String[] deletedRoleNames = role.split(UserCoreConstants.DOMAIN_SEPARATOR);
                // TODO: sabthar, fix this temporary domain name seperator
                String[] deletedRoleNames = role.split("/");
                if (deletedRoleNames.length > 1) {
                    role = deletedRoleNames[1];
                }

                JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(role);
                role = ctx.getRoleName();
                int roleTenantId = ctx.getTenantId();
                boolean isShared = ctx.isShared();

                if (isShared) {
                    sharedRoles.add(role);
                    sharedTenantIds.add(roleTenantId);
                } else {
                    roles.add(role);
                    tenantIds.add(roleTenantId);
                }
            }

        }

        RoleBreakdown breakdown = new RoleBreakdown();

        // Non shared roles and tenant ids
        breakdown.setRoles(roles.toArray(new String[roles.size()]));
        breakdown.setTenantIds(tenantIds.toArray(new Integer[tenantIds.size()]));

        // Shared roles and tenant ids
        breakdown.setSharedRoles(sharedRoles.toArray(new String[sharedRoles.size()]));
        breakdown.setSharedTenantIDs(sharedTenantIds.toArray(new Integer[sharedTenantIds.size()]));

        return breakdown;

    }

    @Override
    protected RoleContext createRoleContext(String roleName) {

        JDBCRoleContext searchCtx = new JDBCRoleContext();
        String[] roleNameParts;

        if (isSharedGroupEnabled()) {
            roleNameParts = roleName.split(UserCoreConstants.TENANT_DOMAIN_COMBINER);
            if (roleNameParts.length > 1 && (roleNameParts[1] == null || roleNameParts[1].equals("null"))) {
                roleNameParts = new String[]{roleNameParts[0]};
            }
        } else {
            roleNameParts = new String[]{roleName};
        }

        int tenantId = -1;
        if (roleNameParts.length > 1) {
            tenantId = Integer.parseInt(roleNameParts[1]);
            searchCtx.setTenantId(tenantId);
        } else {
            tenantId = this.tenantId;
            searchCtx.setTenantId(tenantId);
        }

        if (tenantId != this.tenantId) {
            searchCtx.setShared(true);
        }

        searchCtx.setRoleName(roleNameParts[0]);
        return searchCtx;
    }

    /**
     * Add properties as a batch
     *
     * @param dbConnection
     * @param userName
     * @param properties
     * @param profileName
     * @throws org.wso2.micro.integrator.security.user.api.UserStoreException
     */
    private void addProperties(Connection dbConnection, String userName, Map<String, String> properties,
                               String profileName) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        String type;
        try {
            type = DatabaseCreator.getDatabaseType(dbConnection);
        } catch (Exception e) {
            String msg = "Error occurred while adding user properties for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }

        String sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_PROPERTY + "-" + type);
        if (sqlStmt == null) {
            sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_PROPERTY);
        }
        if (sqlStmt == null) {
            throw new UserStoreException("The sql statement for add user property sql is null");
        }

        PreparedStatement prepStmt = null;
        boolean localConnection = false;

        try {
            if (dbConnection == null) {
                localConnection = true;
                dbConnection = getDBConnection();
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);

            Map<String, String> userAttributes = new HashMap<>();
            for (Map.Entry<String, String> entry : properties.entrySet()) {
                String attributeName = getClaimAtrribute(entry.getKey(), userName, null);
                String attributeValue = entry.getValue();
                userAttributes.put(attributeName, attributeValue);
            }

            for (Map.Entry<String, String> entry : userAttributes.entrySet()) {
                String propertyName = entry.getKey();
                String propertyValue = entry.getValue();
                if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    if (UserCoreConstants.OPENEDGE_TYPE.equals(type)) {
                        batchUpdateStringValuesToDatabase(prepStmt, propertyName, propertyValue, profileName,
                                tenantId, userName, tenantId);
                    } else {
                        batchUpdateStringValuesToDatabase(prepStmt, userName, tenantId, propertyName, propertyValue,
                                profileName, tenantId);
                    }
                } else {
                    batchUpdateStringValuesToDatabase(prepStmt, userName, propertyName, propertyValue, profileName);
                }
            }

            int[] counts = prepStmt.executeBatch();
            if (log.isDebugEnabled()) {
                int totalUpdated = 0;
                if (counts != null) {
                    for (int i : counts) {
                        totalUpdated += i;
                    }
                }

                if (totalUpdated == 0) {
                    log.debug("No rows were updated");
                }
                log.debug("Executed query is " + sqlStmt + " and number of updated rows :: " + totalUpdated);
            }

            if (localConnection) {
                dbConnection.commit();
            }
        } catch (SQLException e) {
            String msg = "Error occurred while updating string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            if (localConnection) {
                DatabaseUtil.closeAllConnections(dbConnection);
            }
            DatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    /**
     * Get the attribute for the provided claim uri and identifier.
     *
     * @param claimURI
     * @param identifier user name or role.
     * @param domainName TODO
     * @return claim attribute value. NULL if attribute is not defined for the
     * claim uri
     * @throws org.wso2.micro.integrator.security.user.api.UserStoreException
     */
    protected String getClaimAtrribute(String claimURI, String identifier, String domainName)
            throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        domainName = realmConfig.getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME);
        String attributeName = null;
        if (domainName != null && !domainName.equals(UserStoreConfigConstants.PRIMARY)) {
            attributeName = claimManager.getAttributeName(domainName, claimURI);
        }
        if (attributeName == null || attributeName.isEmpty()) {
            attributeName = claimManager.getAttributeName(claimURI);
        }

        if (attributeName == null) {
            if (UserCoreConstants.PROFILE_CONFIGURATION.equals(claimURI)) {
                attributeName = claimURI;
            } else if (DISAPLAY_NAME_CLAIM.equals(claimURI)) {
                attributeName = this.realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
            } else {
                throw new UserStoreException("Mapped attribute cannot be found for claim : " + claimURI + " in user " +
                        "store : " + getMyDomainName());
            }
        }

        return attributeName;
    }


    /**
     * Prepare the batch
     *
     * @param prepStmt
     * @param params
     * @throws UserStoreException
     */
    private void batchUpdateStringValuesToDatabase(PreparedStatement prepStmt, Object... params) throws
            UserStoreException {
        try {
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Invalid data provided");
                    } else if (param instanceof String) {
                        prepStmt.setString(i + 1, (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(i + 1, (Integer) param);
                    } else if (param instanceof Date) {
                        prepStmt.setTimestamp(i + 1, new Timestamp(System.currentTimeMillis()));
                    } else if (param instanceof Boolean) {
                        prepStmt.setBoolean(i + 1, (Boolean) param);
                    }
                }
            }
            prepStmt.addBatch();
        } catch (SQLException e) {
            String msg = "Error occurred while updating property values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }
    }

    /**
     *
     */
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
        boolean isExisting = false;

        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if (Boolean.parseBoolean(isUnique) && !UserCoreConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
            String uniquenesSql;
            if (isCaseSensitiveUsername()) {
                uniquenesSql = realmConfig.getUserStoreProperty(JDBCRealmConstants.USER_NAME_UNIQUE);
            } else {
                uniquenesSql = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.USER_NAME_UNIQUE_CASE_INSENSITIVE);
            }
            isExisting = isValueExisting(uniquenesSql, null, userName);
            if (log.isDebugEnabled()) {
                log.debug("The username should be unique across tenants.");
            }
        } else {
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                isExisting = isValueExisting(sqlStmt, null, userName, tenantId);
            } else {
                isExisting = isValueExisting(sqlStmt, null, userName);
            }
        }

        return isExisting;
    }

    /**
     * @param sqlStmt
     * @param dbConnection
     * @param params
     * @return
     * @throws UserStoreException
     */
    protected boolean isValueExisting(String sqlStmt, Connection dbConnection, Object... params)
            throws UserStoreException {
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        boolean isExisting = false;
        boolean doClose = false;
        try {
            if (dbConnection == null) {
                dbConnection = getDBConnection();
                doClose = true; // because we created it
            }
            if (DatabaseUtil.getIntegerValueFromDatabase(dbConnection, sqlStmt, params) > -1) {
                isExisting = true;
            }
            return isExisting;
        } catch (SQLException e) {
            String msg = "Error occurred while checking existence of values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            if (doClose) {
                DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
            }
        }
    }


    /**
     *
     */
    public boolean doCheckExistingRole(String roleName) throws UserStoreException {

        RoleContext roleContext = createRoleContext(roleName);  // TODO if role Name with Shared Role?
        return isExistingJDBCRole(roleContext);
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
                    isValueExisting(sqlStmt, null, roleName, ((JDBCRoleContext) context).getTenantId());
        } else {
            isExisting = isValueExisting(sqlStmt, null, roleName);
        }

        return isExisting;
    }
}

