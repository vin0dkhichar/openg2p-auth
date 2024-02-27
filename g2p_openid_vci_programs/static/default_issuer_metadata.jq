[
    {
        "id": .type,
        "format": .supported_format,
        "scope": .scope,
        "cryptographic_binding_methods_supported": [
            "did:jwk"
        ],
        "credential_signing_alg_values_supported": [
            "RS256"
        ],
        "proof_types_supported": [
            "jwt"
        ],
        "credential_definition": {
            "type": [
                "VerifiableCredential",
                .type
            ],
            "credentialSubject": {
                "given_name": {
                    "display": [
                        {
                            "name": "Given Name",
                            "locale": "en-US"
                        }
                    ]
                },
                "family_name": {
                    "display": [
                        {
                            "name": "Surname",
                            "locale": "en-US"
                        }
                    ]
                }
            }
        },
        "display": [
            {
                "name": "OpenG2P Program Beneficiary Credential",
                "locale": "en",
                "logo": {
                    "url": (.web_base_url + "/g2p_openid_vci_programs/static/description/icon.png"),
                    "alt_text": "a square logo of a OpenG2P"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
            }
        ]
    }
]
