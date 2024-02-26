import json
import logging
import uuid
from datetime import datetime

import pyjq as jq  # pylint: disable=[W7936]
import requests
from cryptography.hazmat.primitives import hashes
from jose import jwt  # pylint: disable=[W7936]
from pyld import jsonld  # pylint: disable=[W7936]

from odoo import api, fields, models, tools

from ..json_encoder import RegistryJSONEncoder
from .constants import (
    DEFAULT_CONTEXT_TO_INCLUDE,
    DEFAULT_CREDENTIAL_SUBJECT_FORMAT,
    DEFAULT_ISSUER_METADATA_TEXT,
)

_logger = logging.getLogger(__name__)


class OpenIDVCIssuer(models.Model):
    _name = "g2p.openid.vci.issuers"
    _description = "OpenID VCI Issuer"

    name = fields.Char(required=True)
    type = fields.Selection(
        [
            (
                "OpenG2PRegistryVerifiableCredential",
                "OpenG2PRegistryVerifiableCredential",
            )
        ],
        required=True,
    )
    scope = fields.Char(required=True)
    supported_format = fields.Selection(
        [("ldp_vc", "ldp_vc")], default="ldp_vc", required=True
    )
    unique_issuer_id = fields.Char(default="did:example:12345678abcdefgh")

    contexts_to_include = fields.Text(default=DEFAULT_CONTEXT_TO_INCLUDE)

    encryption_provider_id = fields.Many2one("g2p.encryption.provider")

    auth_sub_id_type_id = fields.Many2one("g2p.id.type")

    auth_allowed_auds = fields.Text()
    auth_allowed_issuers = fields.Text()
    auth_issuer_jwks_mapping = fields.Text()
    auth_allowed_client_ids = fields.Text()

    credential_subject_format = fields.Text(default=DEFAULT_CREDENTIAL_SUBJECT_FORMAT)
    issuer_metadata_text = fields.Text(default=DEFAULT_ISSUER_METADATA_TEXT)

    @api.model
    def issue_vc(self, credential_request: dict):
        request_proof_type = credential_request["proof"]["proof_type"]
        request_proof_jwt = credential_request["proof"]["jwt"]
        request_proof = None
        if request_proof_type and request_proof_jwt and request_proof_type == "jwt":
            request_proof = jwt.get_unverified_claims(request_proof_jwt)
        else:
            raise ValueError("Only JWT proof supported")

        request_format = credential_request["format"]
        request_types = credential_request["credential_definition"]["type"]
        request_scopes = request_proof.get("scope", "").split()
        if not request_scopes:
            raise ValueError("Scope not found in proof.")

        credential_issuer = self.sudo().search(
            [
                ("supported_format", "=", request_format),
                ("scope", "in", request_scopes),
                ("type", "in", request_types),
            ],
        )
        if credential_issuer and len(credential_issuer):
            credential_issuer = credential_issuer[0]
        else:
            raise ValueError("Invalid combination of scope, type, format")

        request_auth_iss = request_proof["iss"]
        # TODO: Client id validation

        try:
            auth_allowed_iss = (credential_issuer.auth_allowed_issuers or "").split()
            auth_allowed_aud = (credential_issuer.auth_allowed_auds or "").split()
            auth_jwks_mapping = (
                credential_issuer.auth_issuer_jwks_mapping or ""
            ).split()
            jwks = credential_issuer.get_auth_jwks(
                request_auth_iss,
                auth_allowed_iss,
                auth_jwks_mapping,
            )
            jwt.decode(
                request_proof_jwt,
                jwks,
                issuer=auth_allowed_iss,
                options={"verify_aud": False},
            )
            if auth_allowed_aud and (
                (
                    isinstance(request_proof["aud"], list)
                    and set(auth_allowed_aud).issubset(set(request_proof["aud"]))
                )
                or (
                    isinstance(request_proof["aud"], str)
                    and auth_allowed_aud in request_proof["aud"]
                )
            ):
                raise ValueError("Invalid Audience")
        except Exception as e:
            raise ValueError("Invalid proof received") from e

        issue_vc_func = getattr(credential_issuer, f"issue_vc_{credential_issuer.type}")

        return issue_vc_func(
            proof_payload=request_proof,
            credential_request=credential_request,
        )

    def issue_vc_OpenG2PRegistryVerifiableCredential(
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
                ],
                limit=1,
            )
        )
        partner = None
        if not reg_id:
            raise ValueError("ID not found in DB. Invalid Subject Received in proof")

        partner = reg_id.partner_id

        partner_dict = reg_id.partner_id.read()[0]
        reg_id_dict = reg_id.read(["value", "id_type"])[0]

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
                    },
                ),
            ),
        }
        credential_response = {
            "credential": self.sign_and_issue_credential(credential),
            "format": credential_request["format"],
        }
        return credential_response

    def sign_and_issue_credential(self, credential: dict) -> dict:
        self.ensure_one()

        ld_proof = self.build_empty_ld_proof()
        normalised_ld_prood_str = jsonld.normalize(
            ld_proof, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )
        normalized_json_ld_str = jsonld.normalize(
            credential, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )

        signature = self.get_encryption_provider().jwt_sign(
            self.sha256_digest(normalised_ld_prood_str.encode())
            + self.sha256_digest(normalized_json_ld_str.encode()),
            include_payload=False,
            include_certificate=True,
            include_cert_hash=True,
        )
        ld_proof["jws"] = signature
        ret = dict(credential)
        ret["proof"] = ld_proof
        return ret

    def build_empty_ld_proof(self):
        self.ensure_one()
        return {
            "@context": [
                "https://w3id.org/security/v2",
            ],
            "type": "RsaSignature2018",
            "proofPurpose": "assertionMethod",
        }

    def get_auth_jwks(
        self,
        auth_issuer: str,
        auth_allowed_issuers: list[str],
        auth_allowed_jwks_urls: list[str],
    ):
        self.ensure_one()
        jwk_url = None
        try:
            jwk_url = auth_allowed_jwks_urls[auth_allowed_issuers.index(auth_issuer)]
        except Exception:
            jwk_url = f'{auth_issuer.rstrip("/")}/.well-known/jwks.json'
        return requests.get(jwk_url).json()

    def get_encryption_provider(self):
        self.ensure_one()
        prov = self.encryption_provider_id
        if not prov:
            prov = self.env.ref("g2p_encryption.encryption_provider_default")
        return prov

    @api.model
    def get_full_address(self, address: str) -> dict:
        try:
            return json.loads(address)
        except Exception:
            return {"street_address": address}

    @api.model
    def get_image_base64_data_in_url(self, image_base64: str) -> str:
        if not image_base64:
            return None
        image = tools.base64_to_image(image_base64)
        return f"data:image/{image.format.lower()};base64,{image_base64}"

    @api.model
    def sha256_digest(self, data: bytes) -> bytes:
        sha = hashes.Hash(hashes.SHA256())
        sha.update(data)
        return sha.finalize()
