// Drive the real KeeneticOS DOM without changing its router or providers.
(async function () {
    const scenario = window.fixtureScenario;
    const mark = document.body.dataset;
    const by = (selector) => document.querySelector(selector);
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    async function until(label, condition) {
        for (let attempt = 0; attempt < 100; attempt += 1) {
            const result = condition();
            if (result) return result;
            await sleep(100);
        }
        throw new Error(label);
    }

    function pauseForSidebar() {
        return until("stock sidebar did not load", () => by("ndw-menu a[href]")?.closest("ndw-menu"));
    }

    function pauseForKeenProxy() {
        return until("native page did not activate", () => location.pathname === "/keenproxy"
            && by("keenproxy-page ndw-section") && by("ndw-menu"));
    }

    async function clickSidebarLink(path) {
        const menu = await pauseForSidebar();
        const link = menu.querySelector('a[href="' + path + '"]');
        if (!link) throw new Error(path === "/keenproxy" ? "missing-native-menu-link" : "stock link was absent");
        if (link.tabIndex < 0) {
            link.closest(".menu__group").querySelector(".menu__header").click();
            await until("stock menu group did not open", () => link.tabIndex >= 0);
        }
        link.click();
    }

    function fill(input, value) {
        input.value = value;
        input.dispatchEvent(new Event("input", {bubbles: true}));
        input.dispatchEvent(new Event("change", {bubbles: true}));
    }

    async function reachLogin() {
        return until("stock login form did not load", () => location.pathname === "/login"
            && by(".login-form__login input") && by(".login-form__password input"));
    }

    async function logIn() {
        await reachLogin();
        fill(by(".login-form__login input"), "fixture-user");
        fill(by(".login-form__password input"), "fixture-password");
        const submit = await until("stock login button did not enable", () =>
            by(".login-form button[type=submit]:not([disabled])"));
        submit.click();
        await pauseForKeenProxy();
    }

    function dialogButton(label) {
        return Array.from(document.querySelectorAll("button")).find(button =>
            button.textContent.trim() === label);
    }

    async function checkDirtyDraft() {
        await pauseForKeenProxy();
        const draft = by("keenproxy-page #test-draft");
        if (!draft) throw new Error("native draft control was absent");
        fill(draft, "local edit");
        await clickSidebarLink("/opkg");
        const stay = await until("stock leave dialog did not offer Stay", () => dialogButton("Stay"));
        stay.click();
        await until("stock leave dialog did not close", () => !dialogButton("Stay"));
        if (location.pathname !== "/keenproxy" || by("keenproxy-page #test-draft")?.value !== "local edit") {
            throw new Error("draft was lost on cancel");
        }
        await clickSidebarLink("/opkg");
        const leave = await until("stock leave dialog did not offer Leave", () => dialogButton("Leave"));
        leave.click();
        await until("leave confirmation did not navigate", () => location.pathname === "/opkg"
            && !by("keenproxy-page") && by("ndw-menu"));
    }

    async function checkStatusText() {
        by("keenproxy-page #check").click();
        await until("unexpected status display", () =>
            by("keenproxy-page [role=status]")?.textContent === scenario.statusText);
    }

    try {
        switch (scenario.name) {
            case "sidebar":
                await clickSidebarLink("/keenproxy");
                await pauseForKeenProxy();
                break;
            case "login":
                await logIn();
                break;
            case "anonymous":
                await reachLogin();
                if (by("keenproxy-page") || by("ndw-menu")) throw new Error("anonymous saw a protected page");
                break;
            case "readonly":
            case "manager": {
                const menu = await pauseForSidebar();
                if (location.pathname !== "/dashboard" || by("keenproxy-page")
                        || menu.querySelector('a[href="/keenproxy"]')) {
                    throw new Error("protected route or menu exposed to " + scenario.name);
                }
                break;
            }
            case "leave":
                await checkDirtyDraft();
                break;
            case "demo":
                await pauseForKeenProxy();
                if (!by('ndw-menu a[href="/keenproxy"]')) throw new Error("demo did not show the native menu");
                break;
            default:
                await pauseForKeenProxy();
                break;
        }
        if (scenario.statusText) await checkStatusText();
        mark.proof = scenario.name + "-passed";
    } catch (error) {
        mark.proof = error.message;
    }
})();
