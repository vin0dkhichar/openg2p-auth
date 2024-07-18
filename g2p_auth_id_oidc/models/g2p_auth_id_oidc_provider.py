import logging

from odoo import fields, models

_logger = logging.getLogger(__name__)


class G2PAuthIDOidcProvider(models.Model):
    _inherit = "auth.oauth.provider"

    g2p_id_type = fields.Many2one("g2p.id.type", "G2P Registrant ID Type", required=False)

    def oidc_signup_find_existing_partner(self, validation, params):
        if self.g2p_id_type:
            user_id = validation.get("user_id")
            # TODO: Handle expired IDs
            reg_id = self.env["g2p.reg.id"].search(
                [("id_type", "=", self.g2p_id_type.id), ("value", "=", user_id)]
            )
            if reg_id:
                return reg_id.partner_id
        return None

    def oidc_signup_process_name(self, validation, params):
        super().oidc_signup_process_name(validation, params)
        if self.g2p_id_type:
            name_arr = validation.get("name", "").split(" ")
            given_name = name_arr[0]
            family_name = name_arr[-1]
            addl_name = " ".join(name_arr[1:-1])

            name = family_name
            if given_name:
                name += ", " + given_name
            if addl_name:
                name += " " + addl_name

            validation["given_name"] = given_name
            validation["family_name"] = family_name
            validation["addl_name"] = addl_name
            validation["name"] = name.upper()
        return validation

    def oidc_signup_process_reg_ids(self, validation, params):
        if self.g2p_id_type:
            reg_ids = []
            for key, value in validation.items():
                if key.startswith("user_id"):
                    id_type_id = key.removeprefix("user_id")
                    if not id_type_id:
                        id_type_id = self.g2p_id_type.id
                    else:
                        try:
                            id_type_id = int(id_type_id)
                        except Exception:
                            _logger.exception("Invalid Id type mapping. Has to end with `user_id<int>`")
                            continue
                    reg_ids.append(
                        (
                            0,
                            0,
                            {
                                "id_type": id_type_id,
                                "value": value,
                                "expiry_date": None,  # TODO: Set expiry date from config/validation
                            },
                        )
                    )
            validation["reg_ids"] = reg_ids
        return validation

    def oidc_signup_process_phone(self, validation, params):
        if self.g2p_id_type:
            phone = validation.get("phone", "")
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
            validation["phone_number_ids"] = phone_numbers
        return validation

    def oidc_signup_process_other_fields(self, validation, params, **kw):
        self.oidc_signup_process_reg_ids(validation, params)
        if self.g2p_id_type:
            validation["is_registrant"] = True
            validation["is_group"] = False
        super().oidc_signup_process_other_fields(validation, params, **kw)
        return validation
