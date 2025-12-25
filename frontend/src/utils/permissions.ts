// TASK 3.6: Permission checking utilities for RBAC frontend integration

export type Permission =
  | "read:events"
  | "read:alerts"
  | "read:rules"
  | "write:rules"
  | "read:actions"
  | "write:actions"
  | "read:users"
  | "write:users"
  | "admin:system"
  | "read:listeners"
  | "write:listeners";

export interface UserRole {
  id: number;
  name: string;
  description: string;
}

export interface CurrentUser {
  username: string;
  role_id: number | null;
  role_name: string | null;
  active: boolean;
  created_at: string;
  updated_at: string;
  permissions: Permission[];
  role?: UserRole;
}

/**
 * Check if user has a specific permission
 * @param userPermissions Array of permissions the user has
 * @param requiredPermission The permission to check
 * @returns true if user has the permission
 */
export function hasPermission(
  userPermissions: Permission[] | undefined,
  requiredPermission: Permission
): boolean {
  if (!userPermissions || userPermissions.length === 0) {
    return false;
  }
  return userPermissions.includes(requiredPermission);
}

/**
 * Check if user has any of the specified permissions
 * @param userPermissions Array of permissions the user has
 * @param requiredPermissions Array of permissions to check (user needs at least one)
 * @returns true if user has at least one of the required permissions
 */
export function hasAnyPermission(
  userPermissions: Permission[] | undefined,
  requiredPermissions: Permission[]
): boolean {
  if (!userPermissions || userPermissions.length === 0) {
    return false;
  }
  return requiredPermissions.some((perm) => userPermissions.includes(perm));
}

/**
 * Check if user has all of the specified permissions
 * @param userPermissions Array of permissions the user has
 * @param requiredPermissions Array of permissions to check (user needs all)
 * @returns true if user has all of the required permissions
 */
export function hasAllPermissions(
  userPermissions: Permission[] | undefined,
  requiredPermissions: Permission[]
): boolean {
  if (!userPermissions || userPermissions.length === 0) {
    return false;
  }
  return requiredPermissions.every((perm) => userPermissions.includes(perm));
}

/**
 * Check if user has a specific role
 * @param userRoleName The user's role name
 * @param requiredRole The role to check
 * @returns true if user has the role
 */
export function hasRole(
  userRoleName: string | null | undefined,
  requiredRole: string
): boolean {
  return userRoleName === requiredRole;
}

/**
 * Check if user has admin permissions
 * @param userPermissions Array of permissions the user has
 * @returns true if user has admin:system permission
 */
export function isAdmin(userPermissions: Permission[] | undefined): boolean {
  return hasPermission(userPermissions, "admin:system");
}

/**
 * Get role display name with fallback
 */
export function getRoleDisplayName(roleName: string | null | undefined): string {
  if (!roleName) {
    return "No Role";
  }
  return roleName.charAt(0).toUpperCase() + roleName.slice(1);
}

/**
 * Permission to human-readable description mapping
 */
export const PERMISSION_DESCRIPTIONS: Record<Permission, string> = {
  "read:events": "View events",
  "read:alerts": "View alerts",
  "read:rules": "View rules",
  "write:rules": "Create and modify rules",
  "read:actions": "View actions",
  "write:actions": "Create and modify actions",
  "read:users": "View users",
  "write:users": "Manage users",
  "admin:system": "Full system administration",
  "read:listeners": "View listeners",
  "write:listeners": "Manage listeners",
};

