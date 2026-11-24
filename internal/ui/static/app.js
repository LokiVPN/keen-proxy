(() => {
  const dirty = new Set();
  const pending = new WeakSet();

  function warnBeforeLeaving(event) {
    event.preventDefault();
    event.returnValue = "";
  }

  function markDirty(event) {
    const form = event.target.form;
    if (form?.matches("form[data-guard]")) {
      dirty.add(form);
      window.addEventListener("beforeunload", warnBeforeLeaving);
    }
  }

  function clearDirty(event) {
    if (!event.defaultPrevented) {
      dirty.delete(event.target);
      if (dirty.size === 0) window.removeEventListener("beforeunload", warnBeforeLeaving);
    }
  }

  document.addEventListener("input", markDirty);
  document.addEventListener("change", (event) => {
    markDirty(event);
    const control = event.target;
    if (control.form && control.matches("[data-autosubmit]:enabled")) {
      control.form.requestSubmit();
    }
  });
  document.addEventListener("reset", clearDirty);
  document.addEventListener("submit", clearDirty);

  async function refresh(fragment) {
    if (pending.has(fragment)) return;
    pending.add(fragment);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const url = new URL(fragment.dataset.fragment, window.location.origin);
      if (url.origin !== window.location.origin || !url.pathname.startsWith("/fragments/")) return;

      const response = await fetch(url, {
        credentials: "same-origin",
        redirect: "error",
        headers: { Accept: "text/html" },
        signal: controller.signal,
      });
      if (!response.ok || !response.headers.get("Content-Type")?.startsWith("text/html")) return;

      const html = await response.text();
      if (!document.hidden && fragment.isConnected) fragment.innerHTML = html;
    } catch {
      // Retain the last rendered fragment if a refresh fails.
    } finally {
      window.clearTimeout(timeout);
      pending.delete(fragment);
    }
  }

  window.setInterval(() => {
    if (document.hidden) return;
    for (const fragment of document.querySelectorAll("[data-fragment]")) refresh(fragment);
  }, 5000);
})();
