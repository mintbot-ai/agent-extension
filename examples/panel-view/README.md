# Panel view declaration example (AXP 0.5)

This unsigned manifest demonstrates a loopback service, its existing `state:`
bearer authentication contract, an isolated panel with pin/fullscreen hints,
and optional portable enable/disable hooks. It is a structural fixture, not a
published release: the example domain, all-zero digest and script/command
paths are placeholders. No installer, daemon or signing secret is shipped.
Use `axp release` with real artifacts and a publisher key for a real package.

The host owns the service process and the authenticated HTTP/WebSocket proxy.
The application must serve `/desktop/` and use relative assets and WebSocket
URLs (or explicitly support a host-chosen prefix). The optional lifecycle
hooks prepare/clean up activation state; they must not start a second copy of
the host-owned command. The extension generates `state:desktop/token`; it
never receives owner/member host credentials. See SPEC §4.2.1 and §6.5 and the
host guide for isolation and revocation requirements.

Validation: `.venv/bin/python -m axp validate examples/panel-view/agent-extension.json`.
The existing signed `examples/sample-memory/` fixture is intentionally unchanged.
