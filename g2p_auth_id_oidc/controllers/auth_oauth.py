import json
import logging

import werkzeug.urls

from odoo import http
from odoo.http import request

from odoo.addons.auth_oauth.controllers.main import OAuthLogin

_logger = logging.getLogger(__name__)


class OAuthLoginExtended(http.Controller):
    def __init__(self, **kw):
        super(OAuthLoginExtended, self).__init__(**kw)
        OAuthLoginExtended.list_providers_to_replace = OAuthLogin.list_providers
        OAuthLogin.list_providers = OAuthLoginExtended.list_providers
        # TODO: replace the previous list providers method back upon deconstruction of this controller

    def list_providers(self):
        _logger.info("Custom List Providers called.")
        try:
            providers = (
                request.env["auth.oauth.provider"]
                .sudo()
                .search_read([("enabled", "=", True)])
            )
        except Exception:
            providers = []
        for provider in providers:
            return_url = (
                provider.get("redirect_url", None)
                or request.httprequest.url_root + "auth_oauth/signin"
            )
            state = self.get_state(provider)
            params = dict(
                response_type="token",
                client_id=provider["client_id"],
                redirect_uri=return_url,
                scope=provider["scope"],
                state=json.dumps(state),
                # nonce=base64.urlsafe_b64encode(os.urandom(16)),
            )
            provider["auth_link"] = "%s?%s" % (
                provider["auth_endpoint"],
                werkzeug.urls.url_encode(params),
            )
        return providers
