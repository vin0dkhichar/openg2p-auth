import logging
import uuid
from datetime import datetime

import pyjq as jq  # pylint: disable=[W7936]

from odoo import fields, models

from odoo.addons.g2p_openid_vci.json_encoder import RegistryJSONEncoder

_logger = logging.getLogger(__name__)


class BeneficiaryOpenIDVCIssuer(models.Model):
    _inherit = "g2p.openid.vci.issuers"

    type = fields.Selection(
        selection_add=[
            (
                "OpenG2PBeneficiaryVerifiableCredential",
                "OpenG2PBeneficiaryVerifiableCredential",
            )
        ],
        ondelete={"OpenG2PBeneficiaryVerifiableCredential": "cascade"},
    )

    program_id = fields.Many2one("g2p.program")

    def issue_vc_OpenG2PBeneficiaryVerifiableCredential(
        self, proof_payload, credential_request
    ):
        self.ensure_one()
        web_base_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")

        reg_id = (
            self.env["g2p.reg.id"]
            .sudo()
            .search(
                [
                    ("id_type", "=", self.auth_sub_id_type_id.id),
                    ("value", "=", proof_payload["sub"]),
                    (
                        "partner_id.program_membership_ids.program_id",
                        "=",
                        self.program_id.id,
                    ),
                ],
                limit=1,
            )
        )
        partner = None
        if not reg_id:
            raise ValueError(
                "ID not found in DB. Invalid Subject Received in proof. Or person not part of the program."
            )

        partner = reg_id.partner_id
        program_membership_id = partner.program_membership_ids.filtered(
            lambda x: x.program_id.id == self.program_id.id
        )
        if program_membership_id.state != "enrolled":
            raise ValueError("Person not enrolled into program.")

        partner_dict = reg_id.partner_id.read()[0]
        reg_id_dict = reg_id.read(["value", "id_type"])[0]
        program_dict = self.program_id.read()[0]

        curr_datetime = f'{datetime.utcnow().isoformat(timespec = "milliseconds")}Z'
        credential = {
            "@context": jq.first(
                self.contexts_to_include, {"web_base_url": web_base_url}
            ),
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": self.type,
            "issuer": self.unique_issuer_id,
            "issuanceDate": curr_datetime,
            "credentialSubject": jq.first(
                self.credential_subject_format,
                RegistryJSONEncoder.python_dict_to_json_dict(
                    {
                        "web_base_url": web_base_url,
                        "partner": partner_dict,
                        "partner_address": self.get_full_address(partner.address),
                        "partner_face": self.get_image_base64_data_in_url(
                            partner.image_1920
                        ),
                        "reg_id": reg_id_dict,
                        "program": program_dict,
                    }
                ),
            ),
        }
        credential_response = {
            "credential": self.sign_and_issue_credential(credential),
            "format": credential_request["format"],
        }
        return credential_response
