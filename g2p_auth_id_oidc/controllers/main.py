import json
import logging
import traceback
from datetime import datetime

from werkzeug.exceptions import BadRequest

from odoo import http
from odoo.http import request

from odoo.addons.auth_oauth.controllers.main import fragment_to_query_string
from odoo.addons.web.controllers.utils import ensure_db

_logger = logging.getLogger(__name__)


class RegIdOidcController(http.Controller):
    @http.route("/auth_oauth/g2p_registry_id/confirm", type="http", auth="user")
    @fragment_to_query_string
    def g2p_reg_id_confirm(self, **kw):
        return request.render("g2p_auth_id_oidc.g2p_reg_id_confirm", kw)

    @http.route("/auth_oauth/g2p_registry_id/authenticate", type="http", auth="user")
    @fragment_to_query_string
    def g2p_reg_id_authenticate(self, **kw):
        state = json.loads(kw["state"])

        dbname = state["d"]
        if not http.db_filter([dbname]):
            return BadRequest("DB cannot be empty")
        ensure_db(db=dbname)

        provider = state["p"]
        reg_id_id = state["reg_id"]
        response_values = {
            "authentication_status": False,
            "error_exception": None,
        }

        try:
            oauth_provider = request.env["auth.oauth.provider"].sudo().browse(provider)
            reg_id = request.env["g2p.reg.id"].browse(reg_id_id)

            if not oauth_provider.flow.startswith("oidc"):
                # TODO: Support Oauth2 flow also.
                raise BadRequest("Oauth2 Provider not supported!")

            oauth_provider.oidc_get_tokens(
                kw, oidc_redirect_uri=request.httprequest.base_url.replace("authenticate", "confirm")
            )
            reg_id.authentication_status = "authenticated"
            reg_id.last_authentication_time = datetime.now()
            reg_id.last_authentication_user_id = request.env.user.id
            if kw.get("confirm_update", False):
                validation = oauth_provider.oidc_get_validation_dict(kw)
                oauth_provider.oidc_signin_generate_user_values(
                    validation, kw, oauth_partner=reg_id.partner_id, oauth_user=None, create_user=False
                )
                reg_id.partner_id.write(validation)
            response_values["authentication_status"] = True
        except Exception:
            _logger.exception("Encountered error while authenticating Reg Id.")
            response_values["error_exception"] = traceback.format_exc()

        return request.render("g2p_auth_id_oidc.g2p_reg_id_authenticate", response_values)
