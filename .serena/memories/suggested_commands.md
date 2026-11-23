# Commands from the repository root
- make test — language checks, installer tests, secret-scan contract tests, memory-gate unit tests, and tagged Go tests for internal and cmd.
- make check-secrets — checksum-pinned gitleaks scan of commits reachable from HEAD. CI uses the same script: pull requests scan `base..head`; `main` scans HEAD.
- make vet — go vet with the same tags, ./...
- make build — bin/keenproxy (after the memory gates).
- go run -tags with_wireguard,with_awg,with_gvisor ./cmd/keenproxy -dry-run -config examples/config.yaml -arp /dev/null — print artifacts without installing firewall rules. Output includes configuration: never publish it with real keys.
- make build-router / make build-router-lite — cross-compile Linux router binaries with CGO_ENABLED=0 after the memory gates. See the Makefile for architectures and build tags.
- make integration — Docker --privileged, Linux network namespaces; installs packages inside a container and requires network access and Docker. Run for changes to routing, firewall, or DNS behavior.
- CLI flags/default paths: cmd/keenproxy/main.go; tools/probe and separate Go modules: tools/README.md.
- make docs — strict MkDocs build of the EN/RU documentation into site/.
