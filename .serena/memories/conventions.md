# Conventions
- Internal Go packages; model fields use matching yaml/json names, Defaults + Validate, and aggregate configuration errors. Validate before Compile (which contains mustPort).
- model is the source of truth. Schema changes require matching examples, compiler, JSON API and tests; see `mem:features/dns_rules` for schema versions and the v1 backup.
- compile is a pure deterministic transformation; runtime effects belong in daemon/netfilter/engine.
- Use English for source, runtime messages, and shared memories; Russian text lives only in docs/ru and locales/*.ru.yml. Use gofmt, slog, %w error wrapping, standard testing, table cases, and dependency interfaces.
- There is no web/ tree or frontend build; the browser UI will be server-rendered from Go (pending).
- Follow the scoped ub-mode and risk-based verification rules in AGENTS.md; quality tools are not mandatory for every change. Preserve existing uncommitted work.
