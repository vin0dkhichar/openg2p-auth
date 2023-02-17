import logging

from odoo import fields, models

try:
    from jose import jwt
except ImportError:
    logging.getLogger(__name__).debug("jose library not installed")


class G2PAuthIDOidcProvider(models.Model):
    _inherit = "auth.oauth.provider"

    g2p_oidc_id_to_use = fields.Boolean("Use G2P Reg ID", default=False)
    g2p_id_type = fields.Many2one(
        "g2p.id.type", "G2P Registrant ID Type", required=False
    )
    partner_creation_call_validate_url = fields.Boolean(
        help="Whether to call Validation Url for data during Partner Creation",
        default=False,
    )
    partner_creation_validate_response_mapping = fields.Char(
        help="Map Fields from Validation_url response while Partner Creation",
        default=False,
    )
    default_group_user_creation = fields.Many2one(
        "res.groups",
        help="This will be set as default group on user creation",
        default=False,
        required=False,
    )
    login_attribute_mapping_on_user_creation = fields.Char(
        help="Map login attribure from validation response on User Creation",
        default=False,
    )

    # g2p_id_type_key_jwt = fields.Char("G2P Registrant ID Type Key in JWT", default="sub", required=True)
    # static_login_user = fields.Many2one("res.users", "Static User for login", required=False, default=None)
    # enforce_static_login_user = fields.Boolean("Use Static User by default for Login", required=False, default=False)

    # client_assertion_type = fields.Selection(
    #     [
    #         (
    #             "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    #             "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    #         )
    #     ],
    #     required=False,
    # )

    # client_assertion = fields.Char(required=False)

    def _parse_id_token(self, id_token, access_token):
        # This method is only reimplemented here temporarily. To prevent atHash validation
        self.ensure_one()
        res = {}
        header = jwt.get_unverified_header(id_token)
        res.update(
            jwt.decode(
                id_token,
                self._get_key(header.get("kid")),
                algorithms=["RS256"],
                audience=self.client_id,
                access_token=access_token,
                options={"verify_at_hash": False},
            )
        )

        res.update(self._map_token_values(res))
        return res

    def map_validation_response_partner_creation(self, req):
        res = {}
        if self.partner_creation_validate_response_mapping:
            for pair in self.partner_creation_validate_response_mapping.split(" "):
                from_key, to_key = [k.strip() for k in pair.split(":", 1)]
                res[to_key] = req.get(from_key, "")
        return res
