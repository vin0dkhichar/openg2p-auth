# pylint: disable=[W7936]

from typing import Dict, List, Optional, Union

from extendable_pydantic import ExtendableModelMeta
from pydantic import BaseModel


class VCIBaseModel(BaseModel, metaclass=ExtendableModelMeta):
    class Config:
        extra = "allow"


class CredetialRequestProof(VCIBaseModel):
    proof_type: str
    jwt: Optional[str] = None
    cwt: Optional[str] = None


class CredentialRequestDefintion(VCIBaseModel):
    type: List[str]


class CredentialRequest(VCIBaseModel):
    format: str
    proof: Optional[CredetialRequestProof] = None
    credential_definition: CredentialRequestDefintion


class CredentialBaseResponse(VCIBaseModel):
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None


class CredentialResponse(CredentialBaseResponse):
    format: str
    credential: dict
    acceptance_token: Optional[str] = None


class CredentialErrorResponse(CredentialBaseResponse):
    error: str
    error_description: str


class CredentialIssuerDisplayLogoResponse(VCIBaseModel):
    url: str
    alt_text: str


class CredentialIssuerDisplayResponse(VCIBaseModel):
    name: str
    locale: str
    logo: CredentialIssuerDisplayLogoResponse
    background_color: str
    text_color: str


class CredentialIssuerConfigResponse(VCIBaseModel):
    id: Optional[str] = None
    format: str
    scope: str
    cryptographic_binding_methods_supported: List[str]
    credential_signing_alg_values_supported: List[str]
    credential_definition: Dict
    proof_types_supported: Union[Dict, List]
    display: List[CredentialIssuerDisplayResponse]


class CredentialIssuerResponse(VCIBaseModel):
    credential_issuer: str
    credential_endpoint: str
    credentials_supported: Optional[List[CredentialIssuerConfigResponse]] = None
    credential_configurations_supported: Optional[
        Dict[str, CredentialIssuerConfigResponse]
    ] = None
