class ABAC:
    def __init__(self):
        self.policies = []

    def add_policy(self, policy):
        self.policies.append(policy)

    def user_has_access(self, user_attributes, resource_attributes):
        for policy in self.policies:
            if self.evaluate_policy(policy, user_attributes, resource_attributes):
                return True
        return False

    def evaluate_policy(self, policy, user_attributes, resource_attributes):
        user_conditions = policy['user_conditions']
        resource_conditions = policy['resource_conditions']

        # Check user attributes against policy
        for key, value in user_conditions.items():
            if user_attributes.get(key) != value:
                return False

        # Check resource attributes against policy
        for key, value in resource_conditions.items():
            if resource_attributes.get(key) != value:
                return False

        return True

# Example Usage
abac = ABAC()

# Policy: Users with the role 'admin' can access sensitive data
abac.add_policy({
    'user_conditions': {'role': 'admin'},
    'resource_conditions': {'sensitivity': 'high'}
})

# Policy: Editors can access regular data
abac.add_policy({
    'user_conditions': {'role': 'editor'},
    'resource_conditions': {'sensitivity': 'normal'}
})

user_attributes = {'name': 'Alice', 'role': 'admin'}
resource_attributes = {'name': 'Sensitive Document', 'sensitivity': 'high'}

# Check access
print(abac.user_has_access(user_attributes, resource_attributes))  # True

user_attributes = {'name': 'Bob', 'role': 'editor'}
resource_attributes = {'name': 'Regular Document', 'sensitivity': 'normal'}

print(abac.user_has_access(user_attributes, resource_attributes))  # True

user_attributes = {'name': 'Charlie', 'role': 'viewer'}
resource_attributes = {'name': 'Sensitive Document', 'sensitivity': 'high'}

print(abac.user_has_access(user_attributes, resource_attributes))  # False
