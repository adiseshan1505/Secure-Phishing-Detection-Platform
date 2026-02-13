from enum import Enum
from app.models.role_permission import RolePermission


class Permission(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class Role(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"
    GUEST = "guest"


ACL_MATRIX = {
    Role.ADMIN.value: [
        Permission.READ.value, Permission.WRITE.value,
        Permission.DELETE.value, Permission.ADMIN.value
    ],
    Role.ANALYST.value: [
        Permission.READ.value, Permission.WRITE.value
    ],
    Role.USER.value: [
        Permission.READ.value
    ],
    Role.GUEST.value: []
}


class AccessControlManager:
    @staticmethod
    def has_permission(user_role: str, permission: str) -> bool:
        allowed_permissions = ACL_MATRIX.get(user_role, [])
        return permission in allowed_permissions

    @staticmethod
    def check_resource_access(user_role: str, resource: str, permission: str) -> bool:
        if not AccessControlManager.has_permission(user_role, permission):
            return False
        return True

    @staticmethod
    def initialize_acl(db):
        try:
            resources = ["users", "analysis", "logs", "settings"]

            for role, perms in ACL_MATRIX.items():
                for resource in resources:
                    for perm in perms:
                        entry = db.query(RolePermission).filter_by(
                            role=role, permission=perm, resource=resource
                        ).first()

                        if not entry:
                            entry = RolePermission(
                                role=role, permission=perm, resource=resource
                            )
                            db.add(entry)

            db.commit()
        except Exception as e:
            print(f"ACL initialization note: {e}")

    @staticmethod
    def get_acl_matrix():
        return ACL_MATRIX
