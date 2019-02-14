from microkubes.security.chain import SecurityException
from miracle import Acl


class ACLProvider:
    """Implements ACL middleware as a part of the security chain provider.

    :param config: ``dict``, ACL config
    """

    def __init__(self, config):
        self.config = config

        self.acl = Acl()

        policies = config['policies']

        for policy in policies:
            resources = policy['resources']
            actions = policy['actions']
            roles = policy['roles']

            self.acl.add_roles(roles)

            for resource in resources:
                self.acl.add_resource(resource)

            for action in actions:
                for resource in resources:
                    self.acl.add_permission(resource, action)

            for role in roles:
                for action in actions:
                    for resource in resources:
                        self.acl.grant(role, resource, action)


    def execute(self, ctx, req, resp):
        """Execute the security chain provider.

        Checks for several properties in the ACL policy, such as the roles, organizations,
        namespaces, subjects, and based on those it authenticates the user.

        :param ctx: :class:`microkubes.security.auth.SecurityContext`, current ``SecurityContext``.
        :param req: :class:`microkubes.security.chain.Request`, wrapped HTTP Request.
        :param resp: :class:`microkubes.security.chain.Response`, wrapped HTTP Response.

        """
        auth = ctx.get_auth()
        roles = []
        if auth:
            roles = auth.roles
        else:
            raise SecurityException('Not Authorized', status_code=401)

        found_orgs = []
        for policy in self.config['policies']:
            new_orgs = [x for x in policy['organizations'] if x in auth.organizations]
            if len(new_orgs) > 0:
                found_orgs.append(new_orgs)

        if len(found_orgs) == 0:
            raise SecurityException(
                'The user is not authorized to access the resources in this organization',
                status_code=401,
            )

        found_ns = []
        for policy in self.config['policies']:
            new_ns = [x for x in policy['namespaces'] if x in auth.namespaces]
            if len(new_ns) > 0:
                found_ns.append(new_ns)

        if len(found_ns) == 0:
            raise SecurityException(
                'The user is not authorized to access the resources in this namespace',
                status_code=401,
            )

        user_found = False
        for policy in self.config['policies']:
            if len(policy['subjects']) > 0:
                if auth.username in policy['subjects']:
                    user_found = True

        if not user_found:
            raise SecurityException('The user is not authorized.', status_code=401)

        resource = req.path
        method = req.method

        permission = self.get_action(method)
        has_access = self.acl.check_all(roles, resource, permission)
        if not has_access:
            raise SecurityException(
                'The user doesn\'t have a permission for access.', status_code=403
            )

    def __call__(self, ctx, req, resp):
        """Makes the instance of this class callable and thus available for use
        directly as a ``SecurityChain`` provider.
        """
        return self.execute(ctx, req, resp)

    def get_action(self, method):
        """Maps HTTP methods with 'api:read' and 'api:write'

        :param method: ``string``, the HTTP method
        """
        if method == 'GET':
            return 'api:read'
        elif method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return 'api:write'
