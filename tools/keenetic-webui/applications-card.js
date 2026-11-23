// Add a shortcut to the stock Applications grid when the router renders it.
(() => {
    const root = document.querySelector("ndw-root");
    if (!root) return;

    const configured = document.currentScript?.dataset.keenproxyPanelUrl;
    let panel;
    try {
        panel = new URL(configured || `http://${location.hostname}:8086/`);
    } catch {
        return;
    }
    if (!["http:", "https:"].includes(panel.protocol) || panel.username || panel.password) return;

    const marker = "data-keenproxy-application-card";
    const link = document.createElement("a");
    link.setAttribute(marker, "");
    link.href = panel.href;
    link.rel = "noreferrer";

    const title = document.createElement("span");
    title.className = "keenproxy-application-title";
    title.textContent = "KeenProxy";

    const action = document.createElement("span");
    action.className = "keenproxy-application-action";
    const actionLabel = document.createTextNode("");
    const arrow = document.createElement("span");
    arrow.setAttribute("aria-hidden", "true");
    arrow.textContent = "\u2197";
    action.append(actionLabel, arrow);
    link.append(title, action);

    function mountCard() {
        const page = root.querySelector("ndw-page-wrapper.applications");
        const heading = page?.querySelector('ndw-block-header[heading="apps.applications"]');
        if (!heading || (page.querySelector(`[${marker}]`) ?? link) !== link) return;

        actionLabel.nodeValue = document.documentElement.lang.toLowerCase().startsWith("ru")
            ? "\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u043f\u0430\u043d\u0435\u043b\u044c"
            : "Open panel";
        const column = page.querySelector(".applications__container > .applications__column");
        if (column) {
            if (link.parentElement !== column) column.prepend(link);
        } else {
            const controls = page.querySelector(".applications__controls") ?? heading;
            if (controls.nextElementSibling !== link) controls.after(link);
        }
    }

    const observer = new MutationObserver(mountCard);
    observer.observe(root, {childList: true, subtree: true});
    observer.observe(document.documentElement, {attributeFilter: ["lang"]});
    mountCard();
})();
