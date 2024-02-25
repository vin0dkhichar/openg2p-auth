import json
import logging

from odoo import modules

from odoo.addons.base_rest import restapi
from odoo.addons.base_rest_pydantic.restapi import PydanticModel
from odoo.addons.component.core import Component

from ..models.openid_vci import (
    ContextsJson,
    CredentialErrorResponse,
    CredentialIssuerResponse,
    CredentialRequest,
    CredentialResponse,
)

_logger = logging.getLogger(__name__)


class WellknownRestService(Component):
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
        output_param=PydanticModel(CredentialResponse),
    )
    def post_credential(self, credential_request: CredentialRequest):
        try:
            # TODO: Split into smaller steps to better handle errors
            return CredentialResponse(
                **self.env["g2p.openid.vci.issuers"].issue_credential(
                    credential_request.model_dump()
                )
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
            issuer.update({"web_base_url": web_base_url})
            issuer_metadata_string = issuer["issuer_metadata_text"].format(**issuer)
            response["credential_configurations_supported"].update(
                json.loads(issuer_metadata_string)
            )
        return CredentialIssuerResponse(**response)

    @restapi.method(
        [
            (
                [
                    "/context.json",
                ],
                "GET",
            )
        ],
        output_param=PydanticModel(ContextsJson),
    )
    def get_context_json(self):
        web_base_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        with open(
            modules.module.get_resource_path(
                "g2p_openid_vci",
                "static",
                "context.json",
            )
        ) as context_file:
            return ContextsJson(
                json.loads(context_file.read().format(web_base_url=web_base_url))
            )
