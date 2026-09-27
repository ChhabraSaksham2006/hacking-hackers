export const PERMISSIONS = {
  // Alerts
  'alerts.read': 'View alerts and alert details',
  'alerts.update': 'Acknowledge, resolve, assign, add notes',

  // Inference & Ingestion
  'inference.run': 'Trigger a new inference run',
  'model.retrain': 'Retrain the world model',
  'ingestion.create': 'Upload PCAP/CSV captures and start ingestion',
  'simulation.run': 'Run what-if forward simulations',

  // Users
  'users.manage': 'Create, update, delete users and change roles',

  // Reports
  'reports.export': 'Generate and download PDF/CSV reports',

  // Audit
  'audit.read': 'View audit logs',

  // Integrations
  'integrations.manage': 'Manage API keys, webhooks, data sources',

  // Org-level
  'orgs.read': 'View current organisation details',
  'orgs.manage': 'View and manage all organisations',
  'model.promote': 'Promote or rollback model versions globally',

  // Settings
  'settings.read': 'View organisation settings',
  'settings.update': 'Update organisation settings',
} as const;

export type Permission = keyof typeof PERMISSIONS;

export const ROLES = [
  'Analyst',
  'SOC Lead',
  'Admin',
  'Super Admin',
] as const;

export type Role = (typeof ROLES)[number];

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  Analyst: [
    'alerts.read',
    'reports.export',
    'audit.read',
    'orgs.read',
  ],
  'SOC Lead': [
    'alerts.read',
    'alerts.update',
    'inference.run',
    'model.retrain',
    'ingestion.create',
    'simulation.run',
    'reports.export',
    'audit.read',
    'orgs.read',
    'settings.read',
  ],
  Admin: [
    'alerts.read',
    'alerts.update',
    'inference.run',
    'model.retrain',
    'ingestion.create',
    'simulation.run',
    'users.manage',
    'reports.export',
    'audit.read',
    'integrations.manage',
    'orgs.read',
    'settings.read',
    'settings.update',
  ],
  'Super Admin': [
    'alerts.read',
    'alerts.update',
    'inference.run',
    'model.retrain',
    'ingestion.create',
    'simulation.run',
    'users.manage',
    'reports.export',
    'audit.read',
    'integrations.manage',
    'orgs.read',
    'orgs.manage',
    'model.promote',
    'settings.read',
    'settings.update',
  ],
};

/** Check if a role has a specific permission. */
export function roleHasPermission(role: Role | string, permission: Permission): boolean {
  const perms = ROLE_PERMISSIONS[role as Role];
  return perms ? perms.includes(permission) : false;
}
