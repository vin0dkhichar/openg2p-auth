import logging

import pyjq as jq

from odoo.addons.base_rest import restapi
from odoo.addons.base_rest_pydantic.restapi import PydanticModel
from odoo.addons.component.core import Component
from odoo.addons.g2p_openid_vci.json_encoder import RegistryJSONEncoder

from ..models.openid_vci import (
    CredentialBaseResponse,
    CredentialErrorResponse,
    CredentialIssuerResponse,
    CredentialRequest,
    CredentialResponse,
)

_logger = logging.getLogger(__name__)


class OpenIdVCIRestService(Component):
    _name = "openid_vci_base.rest.service"
    _inherit = ["base.rest.service"]
    _usage = "vci"
    _collection = "base.rest.openid.vci.services"
    _description = """
        OpenID for VCI API Services
    """

    @restapi.method(
        [
            (
                [
                    "/credential",
                ],
                "POST",
            )
        ],
        input_param=PydanticModel(CredentialRequest),
        output_param=PydanticModel(CredentialBaseResponse),
    )
    def post_credential(self, credential_request: CredentialRequest):
        try:
            # TODO: Split into smaller steps to better handle errors
            return CredentialResponse(
                **self.env["g2p.openid.vci.issuers"].issue_vc(credential_request.dict())
            )
        except Exception as e:
            _logger.exception("Error while handling credential request")
            # TODO: Remove this hardcoding
            return CredentialErrorResponse(
                error="invalid_scope",
                error_description=f"Invalid Scope. {e}",
                c_nonce="",
                c_nonce_expires_in=1,
            )

    @restapi.method(
        [
            (
                [
                    "/openid-credential-issuer",
                ],
                "GET",
            )
        ],
        output_param=PydanticModel(CredentialIssuerResponse),
    )
    def get_openid_credential_issuer(self):
        vci_issuers = self.env["g2p.openid.vci.issuers"].sudo().search([]).read()
        web_base_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        response = {
            "credential_issuer": web_base_url,
            "credential_endpoint": f"{web_base_url}/api/v1/vci/credential",
            "credential_configurations_supported": {},
        }
        for issuer in vci_issuers:
            issuer["web_base_url"] = web_base_url
            issuer = RegistryJSONEncoder.python_dict_to_json_dict(issuer)
            issuer_metadata = jq.first(issuer["issuer_metadata_text"], issuer)
            response["credential_configurations_supported"].update(issuer_metadata)
        return CredentialIssuerResponse(**response)
