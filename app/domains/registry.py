def load_models() -> None:
    # Explicit imports: shared metadata only, never create_all or dynamic module loading.
    from app.domains.audit.model import AuditEvent  # noqa: F401
    from app.domains.companies.model import Company, CompanyRequest  # noqa: F401
    from app.domains.employees.model import Employee  # noqa: F401
    from app.domains.identity.model import Identity  # noqa: F401
    from app.domains.invitations.model import Invitation  # noqa: F401
    from app.domains.memberships.model import Membership  # noqa: F401
    from app.domains.platform.model import PlatformAdmin, PlatformSettings  # noqa: F401
    from app.domains.rbac.model import (  # noqa: F401
        InvitationRole,
        MembershipRole,
        Permission,
        PermissionDelegation,
        PermissionNamespace,
        Role,
        RolePermission,
        RoleTemplate,
    )
    from app.domains.users.model import User  # noqa: F401
