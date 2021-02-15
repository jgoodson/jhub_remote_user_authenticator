
import os
import re
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode


class RemoteUserLoginHandler(BaseHandler):

    def get(self):
        header_name = self.authenticator.header_name
        remote_user = self.request.headers.get(header_name, "")
        if remote_user == "":
            raise web.HTTPError(401)

        remote_user = re.sub(self.authenticator.header_rewrite_pattern,
                             self.authenticator.header_rewrite_repl,
                             remote_user)

        user = self.user_from_username(remote_user)
        self.set_login_cookie(user)
        next_url = self.get_next_url(user)
        self.redirect(next_url)


class RemoteUserAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    header_rewrite_pattern = Unicode(
        default_value='^(.*)$',
        config=True,
        help="""Python Regex pattern to match for header rewriting.""")

    header_rewrite_repl = Unicode(
        default_value='\g<1>',
        config=True,
        help="""Python Regex replacement for header rewriting.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class RemoteUserLocalAuthenticator(LocalAuthenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    Derived from LocalAuthenticator for use of features such as adding
    local accounts through the admin interface.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    header_rewrite_pattern = Unicode(
        default_value='^(.*)$',
        config=True,
        help="""Python Regex pattern to match for header rewriting.""")

    header_rewrite_repl = Unicode(
        default_value='\g<1>',
        config=True,
        help="""Python Regex replacement for header rewriting.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
