import json
import logging

import requests
import werkzeug.http

from odoo import api, models
from odoo.exceptions import AccessDenied
from odoo.http import request

try:
    from jose import jwt
except ImportError:
    logging.getLogger(__name__).debug("jose library not installed")

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    def _auth_oauth_get_tokens_auth_code_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        code = params.get("code")
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        if oauth_provider.client_assertion_type:
            response = requests.post(
                oauth_provider.token_endpoint,
                data=dict(
                    client_id=oauth_provider.client_id,
                    client_assertion=oauth_provider.client_assertion,
                    client_assertion_type=oauth_provider.client_assertion_type,
                    grant_type="authorization_code",
                    code=code,
                    code_verifier=oauth_provider.code_verifier,  # PKCE
                    redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
                ),
            )
        else:
            auth = None
            if oauth_provider.client_secret:
                auth = (oauth_provider.client_id, oauth_provider.client_secret)
            response = requests.post(
                oauth_provider.token_endpoint,
                data=dict(
                    client_id=oauth_provider.client_id,
                    grant_type="authorization_code",
                    code=code,
                    code_verifier=oauth_provider.code_verifier,  # PKCE
                    redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
                ),
                auth=auth,
            )
        response.raise_for_status()
        response_json = response.json()
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        _logger.info("Here is access token %s", response_json.get("access_token"))
        _logger.info("Here is id token %s", response_json.get("id_token"))
        return response_json.get("access_token"), response_json.get("id_token")

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        """retrieve and sign in the user corresponding to provider and validated access token
        :param provider: oauth provider id (int)
        :param validation: result of validation of access token (dict)
        :param params: oauth parameters (dict)
        :return: user login (str)
        :raise: AccessDenied if signin failed
        This method can be overridden to add alternative signin methods.
        """
        oauth_provider = self.env["auth.oauth.provider"].browse(provider)
        if oauth_provider.g2p_oidc_id_to_use:
            oauth_uid = validation["user_id"]
            try:
                oauth_user = self.search(
                    [
                        ("oauth_uid", "=", oauth_uid),
                        ("oauth_provider_id", "=", provider),
                    ]
                )
                if not oauth_user:
                    raise AccessDenied()
                assert len(oauth_user) == 1
                oauth_user.write({"oauth_access_token": params["access_token"]})
                return oauth_user.login
            except AccessDenied:
                json.loads(params["state"])
                partner = self.generate_partner_signup(
                    oauth_provider, validation, params
                )
                new_user = self.generate_partner_user_signup(
                    partner, oauth_provider, validation, params
                )
                return new_user.login
        else:
            return super(ResUsers, self)._auth_oauth_signin(
                provider, validation, params
            )

    def generate_partner_user_signup(self, partner, oauth_provider, validation, params):
        oauth_uid = validation["user_id"]
        login_attr = oauth_provider.login_attribute_mapping_on_user_creation
        login = validation.get(login_attr, oauth_uid)
        return self.env["res.users"].create(
            {
                "login": login,
                "partner_id": partner.id,
                "oauth_provider_id": oauth_provider.id,
                "oauth_uid": oauth_uid,
                "oauth_access_token": params["access_token"],
                "active": True,
            }
        )

    def generate_partner_signup(self, oauth_provider, validation, params):
        oauth_uid = validation["user_id"]
        if oauth_provider.partner_creation_call_validate_url:
            userinfo_dict = self._auth_oauth_rpc(
                oauth_provider.validation_endpoint, params["access_token"]
            )
            update_dict = oauth_provider.map_validation_response_partner_creation(
                userinfo_dict
            )
            validation.update(update_dict)
            _logger.info(
                "Userinfo JWT payload after validation call. %s",
                json.dumps(userinfo_dict),
            )
            _logger.info(
                "Update dict after validation call. %s", json.dumps(update_dict)
            )
            _logger.info(
                "Validation Dict after validation call. %s", json.dumps(validation)
            )
        try:
            g2p_reg_id = self.env["g2p.reg.id"].search(
                [
                    ("value", "=", oauth_uid),
                    ("id_type", "=", oauth_provider.g2p_id_type.id),
                    ("partner_id.is_registrant", "=", True),
                    ("partner_id.is_group", "=", False),
                ]
            )
            if not g2p_reg_id:
                raise AccessDenied()
            assert len(g2p_reg_id) == 1
            return g2p_reg_id.partner_id
        except AccessDenied:
            # Create partner from validation dictionary
            # TODO: Improve following mapping.
            partner_dict = {
                "given_name": validation.get("name", "").split(" ")[0],
                "family_name": validation.get("name", "").split(" ")[-1],
                "addl_name": " ".join(validation.get("name", "").split(" ")[1:-1]),
                "email": validation.get(
                    "email", "provider_%s_user_%s" % (oauth_provider.id, oauth_uid)
                ),
                "is_registrant": True,
                "is_group": False,
            }
            partner_dict["name"] = self.process_name(
                partner_dict["family_name"],
                partner_dict["given_name"],
                partner_dict["addl_name"],
            )
            partner_dict["gender"] = self.process_gender(validation.get("gender", ""))
            partner_dict["reg_ids"] = self.process_ids(
                oauth_provider.g2p_id_type, oauth_uid
            )
            phone_numbers, primary_phone = self.process_phones(
                validation.get("phone", "")
            )
            if primary_phone:
                partner_dict["phone"] = primary_phone
            if phone_numbers:
                partner_dict["phone_number_ids"] = phone_numbers
            if validation.get("birthdate", None):
                partner_dict["birthdate"] = validation["birthdate"]

            return self.env["res.partner"].create(partner_dict)

    def _auth_oauth_rpc(self, endpoint, access_token):
        # This is recreated to suit that application/jwt response type
        if (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param("auth_oauth.authorization_header")
        ):
            response = requests.get(
                endpoint,
                headers={"Authorization": "Bearer %s" % access_token},
                timeout=10,
            )
        else:
            response = requests.get(
                endpoint, params={"access_token": access_token}, timeout=10
            )

        if response.ok:  # nb: could be a successful failure
            if response.headers.get("content-type"):
                # TODO: Improve the following
                if "application/jwt" in response.headers["content-type"]:
                    return jwt.decode(
                        response.text, None, options={"verify_signature": False}
                    )
                if "application/json" in response.headers["content-type"]:
                    return response.json()
        auth_challenge = werkzeug.http.parse_www_authenticate_header(
            response.headers.get("WWW-Authenticate")
        )
        if auth_challenge.type == "bearer" and "error" in auth_challenge:
            return dict(auth_challenge)

        return {"error": "invalid_request"}

    def process_gender(self, gender):
        return gender.capitalize()

    def process_name(self, family_name, given_name, addl_name):
        name = ""
        if family_name:
            name += family_name + ", "
        if given_name:
            name += given_name + " "
        if addl_name:
            name += addl_name + " "
        return name.upper()

    def process_ids(self, id_type, id_value, status=None, error=None, expiry_date=None):
        return [
            (
                0,
                0,
                {
                    "id_type": id_type.id,
                    "value": id_value,
                    "expiry_date": expiry_date,
                    "status": status,
                    "error": error,
                },
            )
        ]

    def process_phones(self, phone):
        phone_numbers = []
        if phone:
            phone_numbers.append(
                (
                    0,
                    0,
                    {
                        "phone_no": phone,
                    },
                )
            )
        return phone_numbers, phone
