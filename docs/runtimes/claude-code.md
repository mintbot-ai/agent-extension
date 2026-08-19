# Runtime profile: `claude-code` (draft)

Claude Code extends through MCP servers, plugins, skills (`SKILL.md`), hooks
and slash commands. An AXP `claude-code` target describes how to wire an
extension into a user's or project's Claude Code configuration.

## Runtime id / version

`runtime: "claude-code"`; `runtime_version` is the CLI version (`>=2.0`).

## Delivery

`archive` only.

## Scopes

| scope                   | path                                   |
|-------------------------|----------------------------------------|
| `claude-code:skills`    | `~/.claude/skills/` (user) or `<project>/.claude/skills/` |
| `claude-code:plugins`   | `~/.claude/plugins/`                   |
| `claude-code:commands`  | `~/.claude/commands/`                  |
| `config`                | `~/.claude/` / `<project>/.claude/` (settings.json, MCP config) |
| `workspace`             | the project directory                   |

## Environment

SPEC §6.2 plus `AXP_CLAUDE_CODE_SCOPE` (`user` | `project`) and
`AXP_CLAUDE_CODE_PROJECT_DIR` when scope is `project`.

## Component realisation

- `mcp_servers` with `register: "auto"` — added to the MCP server config for
  the chosen scope (`command`/`env` for stdio, `url` for http/sse). This is the
  primary integration path.
- `skills` — `dir` copied/linked into `claude-code:skills`.
- `hooks` — `event` uses Claude Code's hook event names; the host adds the hook
  entry to settings for the chosen scope.
- `prompts` — appended to `CLAUDE.md` at the chosen scope (host-specific).

## Enforcement

`declared` for plugin/hook code; `advisory` for lifecycle scripts where the
host has systemd (see posix profile). MCP servers run as separate processes,
so a host MAY run a stdio server under the same sandbox it uses for lifecycle
scripts and report `advisory` for that component.
