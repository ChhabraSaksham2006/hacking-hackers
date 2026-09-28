import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuthMe } from "./useApi";
import { apiFetch } from "@/lib/api";

export type Role = "Analyst" | "SOC Lead" | "Admin" | "Super Admin";

const ROLE_RANK: Record<Role, number> = {
  Analyst: 1,
  "SOC Lead": 2,
  Admin: 3,
  "Super Admin": 4,
};

export interface RoleMatrixData {
  roles: Role[];
  permissions: Record<string, string>;
  rolePermissions: Record<Role, string[]>;
}

export interface OrgUser {
  _id: string;
  email: string;
  name: string;
  initials: string;
  role: Role;
  orgId: string;
  createdAt?: string;
}

/**
 * Hook providing RBAC permission evaluation and hierarchy checks.
 */
export function usePermissions() {
  const { data: user } = useAuthMe();

  const can = (permission: string): boolean => {
    if (!user) return false;
    if (user.role === "Super Admin") return true;
    return user.permissions?.includes(permission) ?? false;
  };

  const isAtLeast = (minimumRole: Role): boolean => {
    if (!user?.role) return false;
    const userRank = ROLE_RANK[user.role as Role] ?? 0;
    const minRank = ROLE_RANK[minimumRole] ?? 0;
    return userRank >= minRank;
  };

  return {
    user,
    role: user?.role as Role | undefined,
    permissions: user?.permissions ?? [],
    can,
    isAtLeast,
    isAdmin: isAtLeast("Admin"),
    isSocLead: isAtLeast("SOC Lead"),
    isSuperAdmin: user?.role === "Super Admin",
  };
}

/**
 * Fetches the dynamic role-permission catalog.
 */
export function useRoleMatrix() {
  return useQuery({
    queryKey: ["roles", "matrix"],
    queryFn: () => apiFetch<RoleMatrixData>("/api/roles/matrix"),
    staleTime: 60 * 60 * 1000,
  });
}

/**
 * Fetches organization team members.
 */
export function useOrgUsers() {
  return useQuery({
    queryKey: ["roles", "users"],
    queryFn: () => apiFetch<OrgUser[]>("/api/roles/users"),
  });
}

export interface CreateOrgUserInput {
  name: string;
  email: string;
  role: Role;
  password?: string;
}

export interface CreateOrgUserResponse {
  message: string;
  user: OrgUser;
  temporaryPassword?: string;
}

/**
 * Mutation to add a new team member to the organization.
 * Restricted to Admins and SOC Leads.
 */
export function useCreateOrgUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateOrgUserInput) =>
      apiFetch<CreateOrgUserResponse>("/api/roles/users", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles", "users"] });
      queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
  });
}

/**
 * Mutation to update an organization member's role.
 */
export function useUpdateUserRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) =>
      apiFetch<{ message: string; user: OrgUser }>(`/api/roles/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ role }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles", "users"] });
      queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
  });
}

/**
 * Quick role switcher for demo and evaluation environments.
 */
export function useDemoSwitchRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (role: Role) =>
      apiFetch<{ message: string; user: any }>("/api/roles/demo-switch", {
        method: "POST",
        body: JSON.stringify({ role }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      queryClient.invalidateQueries({ queryKey: ["roles"] });
      queryClient.invalidateQueries({ queryKey: ["audit"] });
    },
  });
}
