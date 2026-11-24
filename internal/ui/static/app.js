(() => {
  const dirty = new Set();
  const pending = new WeakSet();

  function warnBeforeLeaving(event) {
    event.preventDefault();
    event.returnValue = "";
  }

  function markDirty(form) {
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

  document.addEventListener("input", (event) => markDirty(event.target.form));
  document.addEventListener("change", (event) => {
    const control = event.target;
    const form = control.form;
    if (!form) return;
    if (control.matches('[data-device-switch][name="full"]')) control.name = "split";
    markDirty(form);
    if (control.matches("[data-autosubmit]:enabled")) {
      form.requestSubmit();
    }
  });
  document.addEventListener("reset", clearDirty);
  document.addEventListener("submit", (event) => {
    const button = event.submitter;
    // The server stages constrained rows and reports how many it skipped.
    if (button?.matches("[data-device-bulk]") && !event.target.querySelector("[data-device-constrained]")) {
      event.preventDefault();
      for (const control of event.target.querySelectorAll("[data-device-switch]")) {
        control.name = "split";
        control.checked = button.value === "split";
      }
      markDirty(event.target);
      return;
    }
    clearDirty(event);
  });
  for (const form of document.querySelectorAll("form[data-guard][data-dirty]")) markDirty(form);
  document.documentElement.classList.add("js");

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
