package org.wso2.dashboard.security.user.core.common;

public class RoleBreakdown {
    private String[] roles;
    private Integer[] tenantIds;
    private String[] sharedRoles;
    private Integer[] sharedTenantIDs;

    public RoleBreakdown() {
    }

    public String[] getRoles() {
        return this.roles;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }

    public Integer[] getTenantIds() {
        return this.tenantIds;
    }

    public void setTenantIds(Integer[] tenantIds) {
        this.tenantIds = tenantIds;
    }

    public String[] getSharedRoles() {
        return this.sharedRoles;
    }

    public void setSharedRoles(String[] sharedRoles) {
        this.sharedRoles = sharedRoles;
    }

    public Integer[] getSharedTenantIDs() {
        return this.sharedTenantIDs;
    }

    public void setSharedTenantIDs(Integer[] sharedTenantIDs) {
        this.sharedTenantIDs = sharedTenantIDs;
    }
}

