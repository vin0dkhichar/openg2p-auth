# Part of OpenG2P. See LICENSE file for full copyright and licensing details.
{
    "name": "G2P Auth: OIDC - Reg ID",
    "category": "G2P",
    "version": "15.0.1.2.0",
    "sequence": 1,
    "author": "OpenG2P",
    "website": "https://openg2p.org",
    "license": "MPL-2",
    "development_status": "Alpha",
    # TODO: Find a replacement for auth_oidc module.
    # Temporarily using auth_oauth.
    "depends": ["auth_oauth", "g2p_registry_base"],
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
