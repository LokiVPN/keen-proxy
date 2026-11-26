# Design direction

- Match the approved KeeneticOS-style management layout with the router back link, session controls, five tabs, and responsive tables. Use the vendored Roboto fonts and CSS light/dark preferences.
- Make status and availability explicit in text. Use visible keyboard focus, associated form labels, and at least 4.5:1 contrast for text in both themes. Keep narrow tabs scrollable and keep actions reachable at 390 px.
- Use native forms and page-scoped saves. Preserve in-progress form input on validation errors and surface revision conflicts. Separate diagnostic status, connection checks and support/update actions.
- Check actual SSR output against the approved design with synthetic fixtures in both locales, themes, viewport sizes, and the view role. Store QA evidence under ignored `.agents-work/`. See `mem:features/ui-redesign` for workflow and `mem:frontend/core` for implementation.
