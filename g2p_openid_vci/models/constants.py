DEFAULT_ISSUER_METADATA_TEXT = """{{
    "{type}": {{
        "format": "{supported_format}",
        "scope": "{scope}",
        "cryptographic_binding_methods_supported": [
            "did:jwk"
        ],
        "credential_signing_alg_values_supported": [
            "RS256"
        ],
        "credential_definition": {{
            "type": [
                "VerifiableCredential",
                "{type}"
            ],
            "credentialSubject": {{
                "given_name": {{
                    "display": [
                        {{
                            "name": "Given Name",
                            "locale": "en-US"
                        }}
                    ]
                }},
                "family_name": {{
                    "display": [
                        {{
                            "name": "Surname",
                            "locale": "en-US"
                        }}
                    ]
                }}
            }}
        }},
        "proof_types_supported": {{
            "jwt": {{
                "proof_signing_alg_values_supported": [
                    "RS256"
                ]
            }}
        }},
        "display": [
            {{
                "name": "OpenG2P Credential",
                "locale": "en-US",
                "logo": {{
                    "url": "{web_base_url}/g2p_openid_vci/static/description/icon.png",
                    "alt_text": "a square logo of a OpenG2P"
                }},
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
            }}
        ]
    }}
}}"""

DEFAULT_CREDENTIAL_SUBJECT_FORMAT = """{
    "vcVer": "VC-V1",
    "id": (.web_base_url  + "/api/v1/registry/individual/" + (.partner.id | tostring)),
    "name": [
        {
            "language": "eng",
            "value": .partner.name
        }
    ],
    "fullName": [
        {
            "language": "eng",
            "value": .partner.name
        }
    ],
    "gender": [
        {
            "language": "eng",
            "value": .partner.gender
        }
    ],
    "dateOfBirth": .partner.birthdate,
    "email": .partner.email,
    "phone": .partner.phone,
    "addressLine1": [
        {
            "language": "eng",
            "value": .partner_address.street_address
        }
    ],
    "province": [
        {
            "language": "eng",
            "value": .partner_address.locality
        }
    ],
    "region": [
        {
            "language": "eng",
            "value": .partner_address.region
        }
    ],
    "postalCode": .partner_address.postal_code,
    "face": .partner_face,
    "UIN": .reg_id.value
}"""

DEFAULT_CONTEXT_TO_INCLUDE = """[
    "{web_base_url}/g2p_openid_vci/static/contexts.json"
]"""
