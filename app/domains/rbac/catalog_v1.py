"""Immutable deployment manifest v1. Add a NEW version, never edit installed sets."""

CORE_PERMISSIONS = (
    ("core.company.read", "Чтение компании", False),
    ("core.company.manage", "Изменение компании", True),
    ("core.members.read", "Чтение участников", False),
    ("core.members.invite", "Приглашение участников", False),
    ("core.members.manage", "Управление участниками", False),
    ("core.members.roles.assign", "Назначение ролей участникам", False),
    ("core.roles.read", "Чтение ролей", False),
    ("core.roles.create", "Создание ролей", False),
    ("core.roles.manage", "Изменение ролей", False),
    ("core.roles.assign", "Назначение ролей", False),
    ("core.roles.revoke", "Снятие ролей", False),
    ("core.permissions.delegate", "Управление делегированием", True),
    ("core.employees.read", "Чтение сотрудников", False),
    ("core.employees.manage", "Управление сотрудниками", False),
    ("core.invitations.read", "Чтение приглашений", False),
    ("core.invitations.manage", "Управление приглашениями", False),
    ("core.ownership.transfer", "Передача владения", True),
)
MEMBER = frozenset({"core.company.read", "core.members.read", "core.employees.read"})
ADMIN = MEMBER | {
    "core.members.manage",
    "core.members.invite",
    "core.employees.manage",
    "core.invitations.read",
    "core.invitations.manage",
    "core.roles.read",
}
OWNER = frozenset(key for key, _, _ in CORE_PERMISSIONS)
SYSTEM_ROLES = {
    "owner": ("Владелец", OWNER),
    "admin": ("Администратор", ADMIN),
    "member": ("Участник", MEMBER),
}
TEMPLATES = (
    (
        "core.template.company_manager",
        "Управляющий компанией",
        ("core.members.read", "core.employees.read", "core.employees.manage"),
    ),
    ("core.template.field_engineer", "Инженер", ("core.company.read", "core.employees.read")),
)
