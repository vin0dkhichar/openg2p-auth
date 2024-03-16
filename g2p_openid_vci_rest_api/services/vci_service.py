import json
import logging

import pyjq as jq
from werkzeug.exceptions import Unauthorized

from odoo.http import request

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
    VCIBaseModel,
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
        token = request.httprequest.headers.get("Authorization", "").removeprefix(
            "Bearer"
        )
        if not token:
            raise Unauthorized("Invalid Bearer Token received.")
        try:
            # TODO: Split into smaller steps to better handle errors
            return CredentialResponse(
                **self.env["g2p.openid.vci.issuers"].issue_vc(
                    credential_request.dict(), token.strip()
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
                    "/.well-known/openid-credential-issuer",
                ],
                "GET",
            )
        ],
        output_param=PydanticModel(CredentialIssuerResponse),
    )
    def get_openid_credential_issuers_all(self):
        return self.get_openid_credential_issuer()

    @restapi.method(
        [
            (
                [
                    "/.well-known/openid-credential-issuer/<string:issuer_name>",
                ],
                "GET",
            )
        ],
        output_param=PydanticModel(CredentialIssuerResponse),
    )
    def get_openid_credential_issuer(self, issuer_name=""):
        search_domain = []
        if issuer_name:
            search_domain.append(("name", "=", issuer_name))
        vci_issuers = (
            self.env["g2p.openid.vci.issuers"].sudo().search(search_domain).read()
        )
        web_base_url = (
            self.env["ir.config_parameter"].sudo().get_param("web.base.url").rstrip("/")
        )
        cred_configs = None
        for issuer in vci_issuers:
            issuer["web_base_url"] = web_base_url
            issuer = RegistryJSONEncoder.python_dict_to_json_dict(issuer)
            issuer_metadata = jq.first(issuer["issuer_metadata_text"], issuer)
            if isinstance(issuer_metadata, list):
                if not cred_configs:
                    cred_configs = []
                cred_configs.extend(issuer_metadata)
            elif isinstance(issuer_metadata, dict):
                if not cred_configs:
                    cred_configs = {}
                cred_configs.update(issuer_metadata)
        response = {
            "credential_issuer": web_base_url,
            "credential_endpoint": f"{web_base_url}/api/v1/vci/credential",
        }
        if isinstance(cred_configs, list):
            response["credentials_supported"] = cred_configs
        elif isinstance(cred_configs, dict):
            response["credential_configurations_supported"] = cred_configs
        return CredentialIssuerResponse(**response)

    @restapi.method(
        [
            (
                [
                    "/.well-known/contexts.json",
                ],
                "GET",
            )
        ],
        output_param=PydanticModel(VCIBaseModel),
    )
    def get_openid_contexts_json(self):
        web_base_url = (
            self.env["ir.config_parameter"].sudo().get_param("web.base.url").rstrip("/")
        )
        context_jsons = (
            self.env["g2p.openid.vci.issuers"].sudo().search([]).read(["contexts_json"])
        )
        final_context = {"@context": {}}
        for context in context_jsons:
            context = context["contexts_json"].strip()
            if context:
                final_context["@context"].update(
                    json.loads(context.replace("web_base_url", web_base_url))[
                        "@context"
                    ]
                )
        return VCIBaseModel(**final_context)
