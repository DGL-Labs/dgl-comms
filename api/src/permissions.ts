// The one place that says who may do what (C1C ADDENDUM-2). Every route checks
// this table, and nothing else decides permissions. An action that is missing,
// or a role that is not listed, is denied.

export const ROLES = ["owner", "admin", "member"] as const;
export type Role = (typeof ROLES)[number];

const EVERY_MEMBER: readonly Role[] = ["owner", "admin", "member"];
const MANAGERS: readonly Role[] = ["owner", "admin"];
const OWNER_ONLY: readonly Role[] = ["owner"];

export const PERMISSIONS = {
  "workspace.read": EVERY_MEMBER,
  "message.post": EVERY_MEMBER,
  "settings.own_notifications": EVERY_MEMBER,
  report_block: EVERY_MEMBER,
  "invite.create": MANAGERS,
  "invite.cancel": MANAGERS,
  // Never the owner: the routes refuse the owner as a target.
  "member.add_remove": MANAGERS,
  "member.change_role": MANAGERS,
  "topic.manage": MANAGERS,
  "key.manage": MANAGERS,
  "workspace.settings": MANAGERS,
  "workspace.transfer_ownership": OWNER_ONLY,
  "workspace.delete": OWNER_ONLY,
} as const satisfies Record<string, readonly Role[]>;

export type Action = keyof typeof PERMISSIONS;

export function isRole(value: unknown): value is Role {
  return (
    typeof value === "string" && (ROLES as readonly string[]).includes(value)
  );
}

export function can(role: Role, action: Action): boolean {
  return PERMISSIONS[action].includes(role);
}
