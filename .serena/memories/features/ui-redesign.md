# Server-rendered management workflow

- `/setup` checks the subscription before enabling it. A fresh setup creates the Home policy from the router's LAN prefix. Replacement keeps the existing subscription ID, reserves, and routing references.
- The five main pages are Overview (`/`), Routing, Devices, Connections, and Diagnostics. The connection import wizard and details live under `/connections/new` and `/connections/id/{id}`. Replacement reuses the existing connection ID.
- Overview's master switch and main connection apply immediately. Routing, Devices, and connection settings apply on Save. Subscription checks and refreshes on Connections preserve in-progress edits. A stale revision is refused before any Apply.
- Setup previews, checked connection imports, and diagnostic results use bounded server-side drafts or tickets. Render provider and user text through `html/template`. Keep credentials out of summaries, view sessions, and logs. Diagnostics shows distinct HTTP, verified HTTPS, and bounded transfer results, with explicit inactive or unknown states.
- Render charts on the server and deliver authorized live updates as HTML fragments. Native page navigation and forms work with JavaScript disabled. See `mem:frontend/core` for access, package boundaries, and CSP.
