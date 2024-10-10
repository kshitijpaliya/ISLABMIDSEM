class RBAC:
    def __init__(self):
        self.roles = {}
        self.users = {}

    def add_role(self, role):
        if role not in self.roles:
            self.roles[role] = set()

    def add_permission_to_role(self, role, permission):
        if role in self.roles:
            self.roles[role].add(permission)

    def assign_role_to_user(self, user, role):
        if user not in self.users:
            self.users[user] = set()
        if role in self.roles:
            self.users[user].add(role)

    def user_has_permission(self, user, permission):
        if user in self.users:
            user_roles = self.users[user]
            for role in user_roles:
                if permission in self.roles[role]:
                    return True
        return False


# Example Usage
rbac = RBAC()
rbac.add_role("admin")
rbac.add_role("editor")
rbac.add_role("viewer")

rbac.add_permission_to_role("admin", "edit")
rbac.add_permission_to_role("admin", "delete")
rbac.add_permission_to_role("editor", "edit")
rbac.add_permission_to_role("viewer", "view")

rbac.assign_role_to_user("alice", "admin")
rbac.assign_role_to_user("bob", "editor")

# Check permissions
print(rbac.user_has_permission("alice", "edit"))  # True
print(rbac.user_has_permission("bob", "delete"))  # False
print(rbac.user_has_permission("bob", "edit"))  # True
print(rbac.user_has_permission("charlie", "view"))  # False
