from typing import Dict, List

from pydantic import BaseModel  # pylint: disable=[W7936]


class CredetialRequestProof(BaseModel):
    proof_type: str
    jwt: str
    cwt: str


class CredentialRequest(BaseModel):
    format: str
    proof: CredetialRequestProof
    credential_definition: dict


class CredentialResponse(BaseModel):
    format: str
    credential: dict
    acceptance_token: str
    c_nonce: str
    c_nonce_expires_in: int


class CredentialErrorResponse(BaseModel):
    error: str
    error_description: str
    c_nonce: str
    c_nonce_expires_in: int


class CredentialIssuerDisplayLogoResponse(BaseModel):
    url: str
    alt_text: str


class CredentialIssuerDisplayResponse(BaseModel):
    name: str
    locale: str
    logo: CredentialIssuerDisplayLogoResponse
    background_color: str
    text_color: str


class CredentialIssuerConfigResponse(BaseModel):
    format: str
    scope: str
    cryptographic_binding_methods_supported: List[str]
    credential_signing_alg_values_supported: List[str]
    credential_definition: Dict
    proof_types_supported: Dict
    display: List[CredentialIssuerDisplayResponse]


class CredentialIssuerResponse(BaseModel):
    credential_issuer: str
    credential_endpoint: str
    credential_configurations_supported: Dict[str, CredentialIssuerConfigResponse]


class ContextsJson(BaseModel, extra="allow"):
    pass
