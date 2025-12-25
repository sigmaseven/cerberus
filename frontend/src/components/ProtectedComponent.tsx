// TASK 3.6: ProtectedComponent wrapper for permission-based rendering

import React, { ReactNode } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { hasPermission, hasAnyPermission, hasAllPermissions, Permission } from '../utils/permissions';

interface ProtectedComponentProps {
  permission?: Permission;
  permissions?: Permission[]; // For hasAnyPermission check
  allPermissions?: Permission[]; // For hasAllPermissions check
  role?: string; // Required role name
  fallback?: ReactNode; // Component to render if permission check fails
  children: ReactNode;
}

/**
 * ProtectedComponent conditionally renders children based on user permissions
 * 
 * @example
 * ```tsx
 * // Require single permission
 * <ProtectedComponent permission="write:rules">
 *   <Button>Create Rule</Button>
 * </ProtectedComponent>
 * 
 * // Require any of multiple permissions
 * <ProtectedComponent permissions={["write:rules", "admin:system"]}>
 *   <Button>Edit Rule</Button>
 * </ProtectedComponent>
 * 
 * // Require specific role
 * <ProtectedComponent role="admin">
 *   <AdminPanel />
 * </ProtectedComponent>
 * 
 * // Custom fallback
 * <ProtectedComponent permission="write:users" fallback={<Alert>No access</Alert>}>
 *   <UserManagement />
 * </ProtectedComponent>
 * ```
 */
export function ProtectedComponent({
  permission,
  permissions,
  allPermissions,
  role,
  fallback = null,
  children,
}: ProtectedComponentProps) {
  const { permissions: userPermissions, roleName, authEnabled } = useAuth();

  // If auth is disabled, always render children
  if (!authEnabled) {
    return <>{children}</>;
  }

  // Check role if specified
  if (role && roleName !== role) {
    return <>{fallback}</>;
  }

  // Check single permission
  if (permission) {
    if (!hasPermission(userPermissions, permission)) {
      return <>{fallback}</>;
    }
  }

  // Check any of permissions
  if (permissions && permissions.length > 0) {
    if (!hasAnyPermission(userPermissions, permissions)) {
      return <>{fallback}</>;
    }
  }

  // Check all permissions
  if (allPermissions && allPermissions.length > 0) {
    if (!hasAllPermissions(userPermissions, allPermissions)) {
      return <>{fallback}</>;
    }
  }

  // If no permission checks specified, render children (just wrapper for consistency)
  if (!permission && !permissions && !allPermissions && !role) {
    return <>{children}</>;
  }

  // All checks passed, render children
  return <>{children}</>;
}

