# RunSecure for OpenAI Codex

Codex doesn't have "plugins/skills" like Claude Code, but it covers the same ground two ways:

1. **`AGENTS.md` (automatic).** Codex reads `AGENTS.md` from the repo root on every session — the same file Claude and humans use. RunSecure ships both:
   - Repo root `AGENTS.md` — operating principles / anti-patterns for **working on** RunSecure (contributor).
   - `skills/using-runsecure/AGENTS-template.md` — a usage-focused `AGENTS.md` to drop into a **consumer** project that adopts RunSecure.
   Nothing to install for the contributor file — open Codex in this repo and it applies.

2. **Custom prompts (slash commands).** The two markdown files in `codex/prompts/` mirror the Claude skills (`using-runsecure`, `developing-runsecure`). Install them so Codex exposes `/use-runsecure` and `/develop-runsecure`:

   ```bash
   mkdir -p ~/.codex/prompts
   cp codex/prompts/use-runsecure.md     ~/.codex/prompts/
   cp codex/prompts/develop-runsecure.md ~/.codex/prompts/
   ```

   Then in Codex: `/use-runsecure` (adopt RunSecure in a project) or `/develop-runsecure` (work on the RunSecure codebase). The filename is the command name; the file body is the instruction.

3. **Adopting RunSecure in YOUR project with Codex.** Copy the consumer AGENTS template into the project you're hardening so Codex (and Claude) follow the egress/hardening rules there:

   ```bash
   cp /path/to/RunSecure/skills/using-runsecure/AGENTS-template.md  your-project/AGENTS.md
   ```

The prompts and the Claude skills are intentionally the same instructions, so behavior is consistent across Codex and Claude. Source of truth for depth remains `README.md`, `SECURITY.md`, and `AGENTS.md`.
