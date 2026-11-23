# Design direction
- The new server-rendered UI follows the KeeneticOS look (stock layout and light/dark themes). The earlier original graphite/lime theme belonged to the removed Vue panel and is retired.
- Diagnostics separates a status summary, connection selection, and individual HTTP/HTTPS/transfer results. Keep unknown states explicit.
- Preserve the shared draft workflow. Keep primary actions visible on small screens and accessible by keyboard.
- Use synthetic fixtures and inspect desktop and narrow layouts in both locales. Keep internal visual QA evidence in ignored `.agents-work/`.
