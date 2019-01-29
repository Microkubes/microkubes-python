from acl import Acl
acl = Acl()


class Policy:
    pass


class ACLProvider:
    def __init__(self, config):
        self.config = config

    def execute(self, ctx, req, resp):
        print 'Execute ACLProvider'

    def __call__(self, ctx, req, resp):
        """Makes the instance of this class callable and thus available for use
        directly as a ``SecurityChain`` provider.
        """
        return self.execute(ctx, req, resp)

    def add_resource(self, resource):
        """Define a resource.

    :param resource: ``string``, Resource name
    """
        acl.add_resource(resource)

    def get_resources(self):
        resources = acl.get_resources()
        return resources

    def add_role(self, role):
        acl.add_role(role)

    def add_roles(self, roles):
        acl.add_roles(roles)

    def get_roles(self):
        roles = acl.get_roles()
        return roles

    def add_permission(self, resource, permission):
        acl.add_permission(resource, permission)

    def get_permissions(self, resource):
        permissions = acl.get_permissions(resource)
        return permissions

    def add(self, structure):
        acl.add(structure)

    def remove_role(self, role):
        acl.remove_role(role)

    def remove_resource(self, resource):
        acl.remove_resource(resource)

    def remove_permission(self, resource, permission):
        acl.remove_permission(resource, permission)

    def clear_all(self):
        acl.clear()

    def get_structure(self):
        structure = acl.get_structure()
        return structure

    def grant_resource_permission(self, role, resource, permission):
        acl.grant(role, resource, permission)

    def add_grants(self, grants):
        acl.grants(grants)

    def revoke_resource_permission(self, role, resource, permission):
        acl.revoke(role, resource, permission)

    def revoke_all_permissions(self, role, resource):
        if resource:
            acl.revoke_all(role, resource)
        else:
            acl.revoke_all(role)

    def check_permission(self, role, resource, permission):
        if permission:
            have_permission = acl.check(role, resource, permission)
        else:
            have_permission = acl.check(role, resource)

        return have_permission

    def check_any(self, roles, resource, permission):
        if roles:
            have_roles = acl.check_any(roles, resource, permission)
        else:
            have_roles = acl.check_any(resource, permission)

        return have_roles

    def check_all(self, roles, resource, permission):
        if roles:
            have_roles = acl.check_all(roles, resource, permission)
        else:
            have_roles = acl.check_all(resource, permission)

        return have_roles

    def list_permissions(self, role, resource):
        permissions = acl.which_permissions(role, resource)

        return permissions

    def list_permissions_any(self, roles, resource):
        permissions = acl.which_permissions_any(roles, resource)

        return permissions

    def list_permissions_all(self, roles, resource):
        permissions = acl.which_permissions_all(roles, resource)

        return permissions

    def get_grants(self, role):
        grants = acl.which(role)

        return grants

    def get_grants_any(self, roles):
        grants = acl.which_any(roles)

        return grants

    def get_grants_all(self, roles):
        grants = acl.which_all(roles)

        return grants

    def current_grants(self):
        grants = acl.show()

        return grants
