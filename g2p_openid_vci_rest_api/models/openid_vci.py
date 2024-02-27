from typing import Dict, List, Optional, Union

from pydantic import BaseModel  # pylint: disable=[W7936]


class CredetialRequestProof(BaseModel):
    proof_type: str
    jwt: Optional[str] = None
    cwt: Optional[str] = None


class CredentialRequestDefintion(BaseModel, extra="allow"):
    type: List[str]


class CredentialRequest(BaseModel):
    format: str
    proof: Optional[CredetialRequestProof] = None
    credential_definition: CredentialRequestDefintion


class CredentialBaseResponse(BaseModel, extra="allow"):
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None


class CredentialResponse(CredentialBaseResponse):
    format: str
    credential: dict
    acceptance_token: Optional[str] = None


class CredentialErrorResponse(CredentialBaseResponse):
    error: str
    error_description: str


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
    id: Optional[str] = None
    format: str
    scope: str
    cryptographic_binding_methods_supported: List[str]
    credential_signing_alg_values_supported: List[str]
    credential_definition: Dict
    proof_types_supported: Union[Dict, List]
    display: List[CredentialIssuerDisplayResponse]


class CredentialIssuerResponse(BaseModel):
    credential_issuer: str
    credential_endpoint: str
    credential_configurations_supported: Union[
        List[CredentialIssuerConfigResponse], Dict[str, CredentialIssuerConfigResponse]
    ]
