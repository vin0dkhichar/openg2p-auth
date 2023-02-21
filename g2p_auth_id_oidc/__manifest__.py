# Part of OpenG2P Registry. See LICENSE file for full copyright and licensing details.
{
    "name": "G2P Auth: OIDC - Reg ID",
    "category": "G2P",
    "version": "15.0.1.1.0",
    "sequence": 1,
    "author": "OpenG2P",
    "website": "https://github.com/OpenG2P/openg2p-auth",
    "license": "Other OSI approved licence",
    "development_status": "Alpha",
    "depends": ["auth_oidc", "g2p_registry_base"],
    "data": [
        "views/g2p_auth_id_oidc_provider.xml",
    ],
    "assets": {
        "web.assets_backend": [],
        "web.assets_qweb": [],
    },
    "demo": [],
    "images": [],
    "application": False,
    "installable": True,
    "auto_install": False,
}
