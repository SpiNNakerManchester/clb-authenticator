import asyncio
import json
import os
from oauthenticator.generic import GenericOAuthenticator
from .refresh_user_mixin import RefreshUserMixin
from jupyterhub.handlers import BaseHandler
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPClientError
from traitlets import Unicode, default
from configparser import ConfigParser
from escapism import escape
import subprocess
import string


class ClbAuthenticator(RefreshUserMixin, GenericOAuthenticator):
    """ Collaboratory authenticator based on generic authenticator."""
    refresh_pre_spawn = True
    auth_refresh_age = 900
    enable_auth_state = True

    drive_url = Unicode(
        config=True,
        help="""The url where the Collab Drive is located""",
    )
    @default("drive_url")
    def _drive_url_default(self):
        return os.environ.get("COLLAB_DRIVE_URL", "")

    drive_mounter_url = Unicode(
        "http://localhost:5000/mount/",
        config=True,
        help="The URL where the mounter API is running"
    )

    def _escape(self, s):
        """Escape a string to docker-safe characters"""
        return escape(
            s.lower(),
            safe=string.ascii_letters + string.digits + '-',
            escape_char='_',
        )


    async def do_drive(self, auth):
        username = self._escape(auth["name"])
        client = AsyncHTTPClient()
        request = HTTPRequest(
            self.drive_url + '/api2/account/token/',
            headers={'Authorization': 'Bearer {token}'.format(
                token=auth['auth_state']['access_token'])},
            connect_timeout=1.0,
            request_timeout=1.0
        )
        drive_token = ""
        try:
            # Get the drive token
            resp = await client.fetch(request)
            drive_token = resp.body.decode('utf-8')

            # Mount the drive
            drive_request = HTTPRequest(
                "{}{}?token={}".format(
                     self.drive_mounter_url, username, drive_token))
            drive_resp = await client.fetch(drive_request)
            drive_json = resp.body

        except HTTPClientError as e:
            self.log.warning("Failed to obtain drive token or mount drive for user {username}.\n"
                             "Exception: {e}".format(username=username, e=e))

    async def authenticate(self, handler, data=None):
        result = await GenericOAuthenticator.authenticate(self, handler, data)
        await self.do_drive(result)
        return result
