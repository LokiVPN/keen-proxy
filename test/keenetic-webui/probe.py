"""Register a local test route in a fingerprinted KeeneticOS bundle."""

import hashlib


PROFILES = {
    "6cb49c39d5ae4873b8977333cd75379420e82acd364eefafc84b458551a87ed8": "W",
    "67eff6ec79ddea853a7ed383fc7cc37d41e1b93d90ea9eb0260973d1ba5e224f": "$",
}
MENU = '{labelL10n:"menu.opkg",pageName:we.OPKG,'
ROUTES = "var _ct=["
WILDCARD = ',{path:"**",redirectTo:"dashboard"}];var wct='

PAGE = r"""
class KeenProxyPage {
    status = U("Check the daemon status");
    draft = "";

    async refresh() {
        try {
            const response = await fetch("/keenproxy-api/status", {cache: "no-store"});
            if (!response.ok) {
                const messages = {
                    401: "KeenProxy sign-in required",
                    403: "KeenProxy access denied",
                    503: "KeenProxy is unavailable",
                };
                this.status.set(messages[response.status] ?? "Status unavailable");
                return;
            }
            const {connections} = await response.json();
            if (!Number.isInteger(connections) || connections < 0) throw new Error("Invalid status response");
            this.status.set("Configured connections: " + connections);
        } catch {
            this.status.set("Status unavailable");
        }
    }

    canDeactivate() {
        return this.draft === "";
    }

    static \u0275fac = type => new (type || KeenProxyPage)();
    static \u0275cmp = F({
        type: KeenProxyPage,
        selectors: [["keenproxy-page"]],
        decls: 10,
        vars: 1,
        consts: [
            ["id", "check", "type", "button"],
            ["role", "status"],
            ["id", "test-draft", "type", "text"],
        ],
        template(flags, page) {
            if (flags & 1) {
                m(0, "ndw-section")(1, "h1");
                A(2, "KeenProxy");
                u();
                m(3, "button", 0);
                P("click", () => page.refresh());
                A(4, "Check status");
                u();
                m(5, "p", 1);
                A(6);
                u();
                m(7, "label");
                A(8, "Test draft");
                m(9, "input", 2);
                P("input", (event) => { page.draft = event.target.value; });
                u()()();
            }
            if (flags & 2) {
                l(6);
                W("", page.status(), "");
            }
        },
        dependencies: [$t],
    });
}
"""

def replace_once(source, anchor, replacement):
    """Reject a different bundle or a changed anchor before applying a patch."""
    if source.count(anchor) != 1:
        raise ValueError("Expected a unique bundle anchor: " + anchor)
    return source.replace(anchor, replacement, 1)


def patch_bundle(source):
    """Register the original test page for a verified stock bundle."""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    interpolation = PROFILES.get(digest)
    if interpolation is None:
        raise ValueError("Unsupported KeeneticOS WebUI bundle")
    page = replace_once(PAGE, 'W("", page.status(), "");',
                        f'{interpolation}("", page.status(), "");')
    menu_item = '{label:"KeenProxy",pageName:"keenproxy",depends:{adminRightsRequired:!0}},'
    page_route = (
        ',{path:"keenproxy",component:Zn,canActivate:[oo],resolve:[ao,so],'
        'children:[{path:"",pathMatch:"full",component:KeenProxyPage,canActivate:[ro,fo],canDeactivate:[Ta]}]}'
    )
    source = replace_once(source, MENU, menu_item + MENU)
    source = replace_once(source, ROUTES, page + ROUTES)
    return replace_once(source, WILDCARD, page_route + WILDCARD)
