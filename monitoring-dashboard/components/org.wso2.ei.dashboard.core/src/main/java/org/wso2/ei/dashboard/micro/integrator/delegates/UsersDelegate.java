/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *
 */

package org.wso2.ei.dashboard.micro.integrator.delegates;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;

import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import org.wso2.dashboard.security.user.core.UserStore;
import org.wso2.dashboard.security.user.core.UserStoreManagerUtils;
import org.wso2.ei.dashboard.core.commons.utils.HttpUtils;
import org.wso2.ei.dashboard.core.commons.utils.ManagementApiUtils;
import org.wso2.ei.dashboard.core.data.manager.DataManager;
import org.wso2.ei.dashboard.core.data.manager.DataManagerSingleton;
import org.wso2.ei.dashboard.core.exception.ManagementApiException;
import org.wso2.ei.dashboard.core.rest.model.Ack;
import org.wso2.ei.dashboard.core.rest.model.AddUserRequest;
import org.wso2.ei.dashboard.core.rest.model.NodeList;
import org.wso2.ei.dashboard.core.rest.model.PasswordRequest;
import org.wso2.ei.dashboard.core.rest.model.User;
import org.wso2.ei.dashboard.core.rest.model.Users;
import org.wso2.ei.dashboard.core.rest.model.UsersInner;
import org.wso2.ei.dashboard.core.rest.model.UsersResourceResponse;
import org.wso2.ei.dashboard.micro.integrator.commons.DelegatesUtil;
import org.wso2.ei.dashboard.micro.integrator.commons.Utils;
import org.wso2.micro.core.util.AuditLogger;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
import org.wso2.micro.integrator.security.user.api.UserStoreManager;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;

import static org.wso2.ei.dashboard.core.commons.Constants.*;

// TODO: sabthar, User an asbstract class and 2 sub class for MI and ICP user delegation
/**
 * Delegate class to handle requests from users page.
 */
public class UsersDelegate {
    private static final Log log = LogFactory.getLog(UsersDelegate.class);
    private static final DataManager dataManager = DataManagerSingleton.getDataManager();
    private static User[] allUserIds;
    private static String prevSearchKey = null;
    private static int count;

    public UsersResourceResponse fetchPaginatedUsers(String groupId, String searchKey, String lowerLimit,
                                                     String upperLimit, String order, String orderBy, String isUpdate)
            throws ManagementApiException {
        DelegatesUtil.logDebugLogs(USERS, groupId, lowerLimit, upperLimit, order, orderBy, isUpdate);
        log.debug("prevSearch key :" + prevSearchKey + ", currentSearch key:" + searchKey);

        // Check if the content needs to be updated or if the search key/resource type has changed
        boolean isUpdatedContent = Boolean.parseBoolean(isUpdate);
        boolean isSearchChanged = (prevSearchKey == null || !prevSearchKey.equals(searchKey));
        boolean isResourceTypeChanged = !USERS.equals(DelegatesUtil.getPrevResourceType());
        if (isUpdatedContent || isSearchChanged || isResourceTypeChanged) {
            allUserIds = getSearchedUsers(groupId, searchKey);
            Arrays.sort(allUserIds);
            count = allUserIds.length;
        }

        int fromIndex = Integer.parseInt(lowerLimit);
        int toIndex = Integer.parseInt(upperLimit);
        Users paginatedUsers = getPaginatedUsersResultsFromMI(allUserIds, fromIndex, toIndex, groupId, order, orderBy);

        UsersResourceResponse response = new UsersResourceResponse();
        response.setResourceList(paginatedUsers);
        response.setCount(count);

        // Update previous state for tracking
        prevSearchKey = searchKey;
        DelegatesUtil.setPrevResourceType(USERS);
        return response;
    }

    public UsersResourceResponse fetchPaginatedIcpUsers(String searchKey, String lowerLimit, String upperLimit,
                                                        String order, String orderBy, String isUpdate)
            throws UserStoreException {
        DelegatesUtil.logDebugLogs(USERS, null, lowerLimit, upperLimit, order, orderBy, isUpdate);
        log.debug("prevSearch key :" + prevSearchKey + ", currentSearch key:" + searchKey);

        // Check if the content needs to be updated or if the search key/resource type has changed
        boolean isUpdatedContent = Boolean.parseBoolean(isUpdate);
        boolean isSearchChanged = (prevSearchKey == null || !prevSearchKey.equals(searchKey));
        boolean isResourceTypeChanged = !USERS.equals(DelegatesUtil.getPrevResourceType());
        if (isUpdatedContent || isSearchChanged || isResourceTypeChanged) {
            String searchPattern = "*".concat(searchKey).concat("*");
            allUserIds = getSearchedIcpUsers(searchPattern);
            Arrays.sort(allUserIds);
            count = allUserIds.length;
        }

        int fromIndex = Integer.parseInt(lowerLimit);
        int toIndex = Integer.parseInt(upperLimit);
        Users paginatedUsers = getPaginatedIcpUsersResult(allUserIds, fromIndex, toIndex, order, orderBy);

        UsersResourceResponse response = new UsersResourceResponse();
        response.setResourceList(paginatedUsers);
        response.setCount(count);

        // Update previous state for tracking
        prevSearchKey = searchKey;
        DelegatesUtil.setPrevResourceType(USERS);
        return response;
    }

    public Ack addUser(String groupId, AddUserRequest request) throws ManagementApiException {
        log.debug("Adding user " + request.getUserId() + " in group " + groupId);
        Ack ack = new Ack(FAIL_STATUS);
        JsonObject payload = createAddUserPayload(request);

        NodeList nodeList = dataManager.fetchNodes(groupId);
        // assumption - In a group, all nodes use a shared user-store
        String nodeId = nodeList.get(0).getNodeId();
        String mgtApiUrl = ManagementApiUtils.getMgtApiUrl(groupId, nodeId);
        String accessToken = dataManager.getAccessToken(groupId, nodeId);
        String url = mgtApiUrl.concat("users");
        CloseableHttpResponse response = null;
        try {
            response = Utils.doPost(groupId, nodeId, accessToken, url, payload);
            ack.setStatus(SUCCESS_STATUS);
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (Exception e) {
                    log.error("Error closing the http response", e);
                }
            }
        }
        return ack;
    }


    public Ack addUserIcp(AddUserRequest request) throws UserStoreException {
        log.debug("Adding user " + request.getUserId() + " to icp");
        UserStoreManager manager = UserStoreManagerUtils.getUserStoreManager();
        synchronized (this) {
            String[] roleList  = request.isIsAdmin() ? new String[]{"admin"}: new String[]{};
            manager.addUser(request.getUserId(), request.getPassword(), roleList, null, null, false);
        }
        Ack ack =  new Ack(SUCCESS_STATUS);
        return ack;
    }

    public Ack updateUserPassword(String groupId, PasswordRequest request, String accessToken)
            throws ManagementApiException {
        Ack ack = new Ack(FAIL_STATUS);
        JsonObject payload = createUserUpdatePasswordPayload(request);

        NodeList nodeList = dataManager.fetchNodes(groupId);
        String nodeId = nodeList.get(0).getNodeId();
        String mgtApiUrl = ManagementApiUtils.getMgtApiUrl(groupId, nodeId);
        String userId = request.getUserId();
        String url = mgtApiUrl.concat("users/");
        if (userId.contains(DOMAIN_SEPARATOR)) {
            String[] parts = userId.split(DOMAIN_SEPARATOR);
            // parts[0] = domain, parts[1] = userId
            url = url.concat(urlEncode(parts[1])).concat("?domain=").concat(urlEncode(parts[0]));
        } else {
            url = url.concat(urlEncode(userId));
        }
        CloseableHttpResponse response = null;
        try {
            response = Utils.doPatch(groupId, nodeId, accessToken, url, payload);
            // TODO: sabthar, this logic seems wrong
            ack.setStatus(SUCCESS_STATUS);
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (Exception e) {
                    log.error("Error closing the http response. ", e);
                }
            }
        }
        return ack;
    }

    public Ack updateUserPasswordIcp(PasswordRequest request, String performedBy) throws UserStoreException {
        String user = request.getUserId();
        if (log.isDebugEnabled()) {
            log.debug("Request received to update user credentials: " + user);
        }
        // TODO: sabthar, set the performed by user from request context. This need to set from security handler/Authentication filter
//        String performedBy =  Utils.getStringPropertyFromMessageContext(messageContext, USERNAME_PROPERTY);
        if (Objects.isNull(performedBy)) {
            log.warn(
                    "Update a user without authenticating/authorizing the request sender. Adding "
                            + "authentication and authorization handlers is recommended.");
        }
        if (request.getNewPassword() != null && request.getConfirmPassword() != null) {
            String newPassword = request.getNewPassword();
            String confirmPassword = request.getConfirmPassword();
            String oldPassword = request.getOldPassword();
            if (newPassword.equals(confirmPassword)) {
                UserStoreManager userStoreManager = UserStoreManagerUtils.getUserStoreManager();
                try {
                    synchronized (this) {
                        String[] userRoles = userStoreManager.getRoleListOfUser(user);
                        String[] performerRoles = userStoreManager.getRoleListOfUser(performedBy);
                        if (user.equals(performedBy)) {
                            if (oldPassword == null) {
                                throw new UserStoreException("The current user password cannot be null.");
                            }
                            userStoreManager.updateCredential(user, newPassword, oldPassword);
                            // TODO: sabthar, this is wrong, instead of ADMIN need to obtain the value from super_admin.username
                        } else if (ADMIN.equals(performedBy)) {
                            userStoreManager.updateCredentialByAdmin(user, newPassword);
                        } else if (Arrays.asList(performerRoles).contains(ADMIN) &&
                                !Arrays.asList(userRoles).contains(ADMIN)) {
                            userStoreManager.updateCredentialByAdmin(user, newPassword);
                        } else if (Arrays.asList(performerRoles).contains(ADMIN) &&
                                Arrays.asList(userRoles).contains(ADMIN)) {
                            throw new UserStoreException(
                                    "Only a super admin user can update the credentials of another admin.");
                        } else {
                            throw new UserStoreException("Only your own credentials can be updated by a user.");
                        }
                    }
                } catch (UserStoreException e) {
                    throw new UserStoreException("Failed to update user password. Please check the current " +
                            "password entered and retry.", e);
                }
            } else {
                throw new UserStoreException("New password and re-typed password does not match.");
            }
        } else {
            throw new UserStoreException("New password or re-typed password is missing in the payload.");
        }
        return new Ack(SUCCESS_STATUS);
    }

    public Ack deleteUser(String groupId, String userId, String domain) throws ManagementApiException {
        if (StringUtils.isEmpty(domain)) {
            log.debug("Deleting user " + userId + " in group " + groupId);
        } else {
            log.debug("Deleting user " + userId + " in domain " + domain + " in group " + groupId);
        }
        Ack ack = new Ack(FAIL_STATUS);
        NodeList nodeList = dataManager.fetchNodes(groupId);
        // assumption - In a group, all nodes use a shared user-store
        String nodeId = nodeList.get(0).getNodeId();
        String mgtApiUrl = ManagementApiUtils.getMgtApiUrl(groupId, nodeId);
        String accessToken = dataManager.getAccessToken(groupId, nodeId);
        String url = mgtApiUrl.concat("users/").concat(urlEncode(userId));
        if (!StringUtils.isEmpty(domain)) {
            url = url.concat("?domain=").concat(urlEncode(domain));
        }
        try (CloseableHttpResponse httpResponse = Utils.doDelete(groupId, nodeId, accessToken, url)) {
            if (httpResponse.getStatusLine().getStatusCode() != 200) {
                log.error("Error occurred while deleting user " + userId + " in group " + groupId);
                String message = HttpUtils.getJsonResponse(httpResponse).get("Error").getAsString();
                ack.setMessage(message);
                return ack;
            }
            ack.setStatus(SUCCESS_STATUS);
            return ack;
        } catch (IOException e) {
            throw new ManagementApiException("Error while deleting user", 500);
        }
    }


    public Ack deleteUserIcp(String userId, String domain) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Request received to delete the user: " + userId);
        }
        // TODO: sabthar, set the performed by user from request context. This need to set from security handler/Authentication filter
        String performedBy = null;
        if (Objects.isNull(performedBy)) {
            log.warn(
                    "Deleting a user without authenticating/authorizing the request sender. Adding "
                            + "authentication and authorization handlers is recommended.");
        } else {
            if (performedBy.equals(userId)) {
                throw new IllegalArgumentException(
                        "Attempt to delete the logged in user. Operation not allowed. Please login "
                                + "from another user.");
            }
        }
        UserStoreManager userStoreManager = UserStoreManagerUtils.getUserStoreManager();
        String[] roles = userStoreManager.getRoleListOfUser(userId);

        // TODO: sabthar, revisit this logic. This should be read from config
//        if (ADMIN.equals(performedBy)) {
//            userStoreManager.deleteUser(user);
//        } else
        if (!Arrays.asList(roles).contains(ADMIN)) {
            userStoreManager.deleteUser(userId);
        } else {
            log.error("Only super admin user can delete admins");
            throw new UserStoreException("Only super admin user can delete admins");
        }
        return new Ack(SUCCESS_STATUS);
    }


    private JsonObject createAddUserPayload(AddUserRequest request) {
        JsonObject payload = new JsonObject();
        payload.addProperty("userId", request.getUserId());
        String domain = request.getDomain();
        if (!StringUtils.isEmpty(domain)) {
            payload.addProperty("domain", domain);
        }
        payload.addProperty("password", request.getPassword());
        payload.addProperty("isAdmin", request.isIsAdmin().toString());
        return payload;
    }

    private JsonObject createUserUpdatePasswordPayload(PasswordRequest request) {
        JsonObject payload = new JsonObject();
        payload.addProperty("newPassword", request.getNewPassword());
        payload.addProperty("confirmPassword", request.getConfirmPassword());
        payload.addProperty("oldPassword", request.getOldPassword());
        return payload;
    }

    private static User[] getSearchedUsers(String groupId, String searchKey) throws ManagementApiException {
        NodeList nodeList = dataManager.fetchNodes(groupId);
        // assumption - In a group, users of all nodes in the group should be identical
        String nodeId = nodeList.get(0).getNodeId();
        String mgtApiUrl = ManagementApiUtils.getMgtApiUrl(groupId, nodeId);
        String accessToken = dataManager.getAccessToken(groupId, nodeId);
        JsonArray usersList = DelegatesUtil.getResourceResultList(groupId, nodeId, "users", mgtApiUrl,
                accessToken, searchKey);
        return new Gson().fromJson(usersList, User[].class);
    }

    private static User[] getSearchedIcpUsers(String searchKey) throws UserStoreException {
        return Arrays.stream(UserStoreManagerUtils.getUserStoreManager().listUsers(searchKey, -1))
                .map(User::new).toArray(User[]::new);
    }

    private Users getPaginatedIcpUsersResult(User[] userArrary, int lowerLimit, int upperLimit,
                                             String order, String orderBy) throws UserStoreException {
        try {
            upperLimit = Math.min(userArrary.length, upperLimit);
            lowerLimit = Math.min(lowerLimit, upperLimit);
            User[] paginatedUsersArray = Arrays.copyOfRange(userArrary, lowerLimit, upperLimit);
            Users users = queryUserInfo(paginatedUsersArray);
            if ("desc".equalsIgnoreCase(order)) {
                Collections.reverse(users);
            }
            return users;
        } catch (IndexOutOfBoundsException e) {
            log.error("Index values are out of bound", e);
        } catch (IllegalArgumentException e) {
            log.error("Illegal arguments for index values", e);
        }
        return null;
    }

    private static @NotNull Users queryUserInfo(User[] users) throws UserStoreException {
        Users resultList = new Users();
        for (User user : users) {
            String[] roles = UserStoreManagerUtils.getUserStoreManager().getRoleListOfUser(user.getUserId());

            JsonObject userDetails = new JsonObject();
            userDetails.addProperty(USER_ID, user.getUserId());
            userDetails.addProperty(IS_ADMIN, UserStoreManagerUtils.isAdmin(user.getUserId()));

            JsonArray rolesArray = new JsonArray();
            Arrays.stream(roles).forEach(rolesArray::add);
            userDetails.add(ROLES, rolesArray);

            UsersInner usersInner = new UsersInner();
            usersInner.userId(user.getUserId());
            usersInner.setDetails(userDetails.toString());

            resultList.add(usersInner);
        }
        Collections.sort(resultList);
        return resultList;
    }

    private Users getPaginatedUsersResultsFromMI(User[] users, int lowerLimit, int upperLimit, String groupId,
                                                 String order, String orderBy) throws ManagementApiException {
        Users resultList = new Users();
        try {
            upperLimit = Math.min(users.length, upperLimit);
            lowerLimit = Math.min(lowerLimit, upperLimit);
            users = Arrays.copyOfRange(users, lowerLimit, upperLimit);

            // creating the URL and fetch role info of user in the current page
            fetchUserInfo(users, groupId, resultList);
            Collections.sort(resultList);

            if ("desc".equalsIgnoreCase(order)) {
                Collections.reverse(resultList);
            }
            return resultList;

        } catch (IndexOutOfBoundsException e) {
            log.error("Index values are out of bound", e);
        } catch (IllegalArgumentException e) {
            log.error("Illegal arguments for index values", e);
        }
        return null;
    }

    /**
     * Fetch individual user details only for the user of the current page.
     *
     * @param users      all users
     * @param groupId    groupId
     * @param resultList list of user details
     * @throws ManagementApiException error occurred while fetching user details.
     */
    private void fetchUserInfo(User[] users, String groupId, Users resultList)
            throws ManagementApiException {
        NodeList nodeList = dataManager.fetchNodes(groupId);
        String nodeId = nodeList.get(0).getNodeId();
        String mgtApiUrl = ManagementApiUtils.getMgtApiUrl(groupId, nodeId);
        String url = mgtApiUrl.concat("users/");
        for (User user : users) {
            UsersInner usersInner = getUserDetails(groupId, nodeId, url, user.getUserId());
            resultList.add(usersInner);
        }
    }

    private static UsersInner getUserDetails(String groupId, String nodeId, String url,
                                             String userId) throws ManagementApiException {
        UsersInner usersInner = new UsersInner();
        usersInner.setUserId(userId);
        String getUsersDetailsUrl;
        if (userId.contains(DOMAIN_SEPARATOR)) {
            String[] parts = userId.split(DOMAIN_SEPARATOR);
            getUsersDetailsUrl = url.concat(urlEncode(parts[1])).concat("?domain=").concat(urlEncode(parts[0]));
        } else {
            getUsersDetailsUrl = url.concat(urlEncode(userId));
        }
        String accessToken = dataManager.getAccessToken(groupId, nodeId);
        try (CloseableHttpResponse userDetailResponse = Utils.doGet(groupId, nodeId, accessToken, getUsersDetailsUrl)) {
            String userDetail = HttpUtils.getStringResponse(userDetailResponse);
            usersInner.setDetails(userDetail);
            return usersInner;
        } catch (IOException e) {
            throw new ManagementApiException("Error while retrieving user details", 500);
        }
    }

    private static String urlEncode(String userId) {
        try {
            return URLEncoder.encode(userId, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            log.error("Error occurred while encoding user id " + userId, e);
            return userId;
        }
    }
}
