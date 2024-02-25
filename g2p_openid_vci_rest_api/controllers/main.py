from odoo.addons.base_rest.controllers.main import RestController


class OpenIDVCIController(RestController):
    _root_path = "/api/v1/"
    _collection_name = "base.rest.openid.vci.services"
    _default_auth = "public"
