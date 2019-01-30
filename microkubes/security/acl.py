class ACLProvider:
    """Implements ACL middleware as a part of the security chain provider.

        :param macl: :class:`flask_miracle.Acl`, current ``ACL`` instance
    """

    def __init__(self, macl):
        self.macl = macl

    def execute(self, ctx):
        """Execute the security chain provider.

        Gets the roles for the authenticated user which are set as current
        roles for the ACL.

        :param ctx: :class:`microkubes.security.auth.SecurityContext`, current ``SecurityContext``.

        """

        roles = ctx.get_auth().roles

        self.macl.set_current_roles(roles)

    def __call__(self, ctx, req, resp):
        """Makes the instance of this class callable and thus available for use
        directly as a ``SecurityChain`` provider.
        """
        return self.execute(ctx)
