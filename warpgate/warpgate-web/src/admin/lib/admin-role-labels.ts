const BUILTIN_ADMIN_ROLE_NAME = 'warpgate:admin'

export function adminRoleDisplayName(name: string): string {
    return name === BUILTIN_ADMIN_ROLE_NAME
        ? 'SecureAccess Administrator'
        : name
}

export function adminRoleDisplayDescription(
    name: string,
    description: string | undefined,
): string | undefined {
    if (
        name === BUILTIN_ADMIN_ROLE_NAME &&
        description === 'Built-in admin role'
    ) {
        return 'Built-in SecureAccess administrator role'
    }
    return description
}
