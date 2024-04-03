import base64
import hashlib
import json
import secrets

from werkzeug.urls import url_encode

from odoo import api, fields, models


class G2PSelfServiceOauthProvider(models.Model):
    _inherit = "auth.oauth.provider"

    g2p_self_service_allowed = fields.Boolean("Allowed in Self Service Portal", default=False)
    g2p_service_provider_allowed = fields.Boolean("Allowed in Service Provider Portal", default=False)
    g2p_portal_login_image_icon_url = fields.Text()
    g2p_portal_oauth_callback_url = fields.Char()

    @api.model
    def get_portal_auth_providers(
        self,
        domain=(("enabled", "=", True),),
        redirect="/selfservice",
        base_url="",
        db_name="",
    ):
        """
        base_url example: request.httprequest.url_root.rstrip("/")
        db_name example: request.session.db
        """
        if redirect.startswith("/"):
            redirect = base_url + redirect
        oauth_redirect_uri = f"{base_url}/auth_oauth/signin"
        providers = self.search_read(domain)
        for provider in providers:
            params = dict(
                response_type="token",
                client_id=provider["client_id"],
                redirect_uri=oauth_redirect_uri,
                scope=provider["scope"],
                state=json.dumps(dict(d=db_name, p=provider["id"], r=redirect), separators=(",", ":")),
            )
            flow = provider.get("flow")
            if flow in ("id_token", "id_token_code"):
                response_type = "id_token token"
                if flow == "id_token_code":
                    response_type = "code"
                params.update(
                    dict(
                        response_type=response_type,
                        nonce=secrets.token_urlsafe(),
                        code_challenge=base64.urlsafe_b64encode(
                            hashlib.sha256(provider["code_verifier"].encode("ascii")).digest()
                        ).rstrip(b"="),
                        code_challenge_method="S256",
                    )
                )
            extra_auth_params = json.loads(provider.get("extra_authorize_params") or "{}")
            params.update(extra_auth_params)
            provider["auth_link"] = f"{provider['auth_endpoint']}?{url_encode(params)}"
        return providers
