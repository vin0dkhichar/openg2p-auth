/** @odoo-module **/

import {_t} from "@web/core/l10n/translation";
import {registry} from "@web/core/registry";
import {Component, xml, useState} from "@odoo/owl";

export class RegIdAuthStatus extends Component {
    static template = xml`<t t-if="showWidget">
            <div t-att-class="statusClass">
                <t t-out="renderStatus()" />
            </div>
            <button t-att-class="buttonClass" t-on-click="authenticateButtonClick">
                Authenticate
            </button>
        </t>`;

    setup() {
        this.statusClass = ""; // TODO: get from field options from view
        this.buttonClass = ""; // TODO: get from field options from view
        this.showWidget = this.props.record.data.auth_oauth_provider_id ? true : false;
        this.statusSelectionObject = Object.fromEntries(
            this.props.record.fields.authentication_status.selection
        );

        var self = this;
        this.props.record.model.orm
            .call(this.props.record.resModel, "get_auth_oauth_provider", [this.props.record.resId])
            .then((result) => {
                self.authProvider = result;
            });
    }

    renderStatus() {
        let status = this.props.record.data.authentication_status;
        return _t(this.statusSelectionObject[status]);
    }

    authenticateButtonClick() {
        let windowFeatures = `popup,height=${(screen.height * 2) / 3},width=${screen.width / 2}`;
        window.open(this.authProvider.auth_link, "", windowFeatures);
    }
}

export const regIdAuthStatusField = {
    component: RegIdAuthStatus,
    displayName: _t("Authentication Status"),
    supportedTypes: ["selection", "many2one", "char"],
    extractProps: ({decorations}) => {
        return {decorations};
    },
};

registry.category("fields").add("g2p_auth_id_oidc.reg_id_auth_status", regIdAuthStatusField);
