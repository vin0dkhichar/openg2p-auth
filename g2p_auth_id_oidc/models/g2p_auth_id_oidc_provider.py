from odoo import fields, models


class G2PAuthIDOidcProvider(models.Model):
    _inherit = "auth.oauth.provider"

    g2p_oidc_id_to_use = fields.Boolean("Use G2P Reg ID", default=False)
    g2p_id_type = fields.Many2one("g2p.id.type", "G2P Registrant ID Type", required=False)
    partner_creation_call_validate_url = fields.Boolean(
        help="Whether to call Validation Url for data during Partner Creation",
        default=False,
    )
    partner_creation_validate_response_mapping = fields.Char(
        help="Map Fields from Validation_url response while Partner Creation",
        default=(
            "name:name "
            "email:email "
            "phone_number:phone "
            "birthdate:birthdate "
            "gender:gender "
            "address:address "
            "picture:picture"
        ),
    )
    partner_creation_date_format = fields.Char(
        help="Format of date to be used while Partner Creation",
        default="%Y/%m/%d",
    )
    default_group_user_creation = fields.Many2one(
        "res.groups",
        help="This will be set as default group on user creation",
        default=False,
        required=False,
    )
    login_attribute_mapping_on_user_creation = fields.Char(
        help="Map login attribure from validation response on User Creation",
        default="email",
    )

    def map_validation_response_partner_creation(self, req):
        res = {}
        if self.partner_creation_validate_response_mapping:
            for pair in self.partner_creation_validate_response_mapping.split(" "):
                if pair:
                    from_key, to_key = (k.strip() for k in pair.split(":", 1))
                    res[to_key] = req.get(from_key, "")
        return res
