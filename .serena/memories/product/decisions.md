# Product decisions
- Focus on Keenetic and Netcraze with Entware. Use embedded sing-box and a server-rendered interface that follows the KeeneticOS look. Maintain both English and Russian UI.
- Keep country groups distinct from domain and IP entries. Explicit group rules precede country rules within routed policies; global block rules run first. Invert the union of excluded countries.
- Prefer readable TLS SNI and HTTP Host. Apply DNS-derived IP rules only when no readable hostname exists.
- Keep DNS routes and direct fallback explicit. Encrypted DNS alone does not establish tunnel routing or prove leak prevention.
- Failover follows an ordered chain with hysteresis. Allow direct fallback only when explicitly configured.
- Keep one applied YAML configuration. Page-scoped Save and the immediate Overview controls use the daemon's revision-checked Apply path. Preview, imports, and staged form edits leave the applied settings untouched until confirmed.
- Explain routing decisions through local loopback journals and the redacted Diagnostics ZIP. Keep secrets masked in connection editing and omit them from exported diagnostics.
