# Unauthenticated Self-Update: git pull + npm install + build via a zero-arg tool

- **Project**: Heratiki/locallama-mcp
- **Commit**: 3af4d831c80b61a15d81b8526db46c4185299714 (v1.31.4)
- **Tool**: `update_server`  (inputSchema: `properties: {}` — no arguments)
- **Class**: design / privilege — unauthenticated code fetch+build+reload
- **Status**: POTENTIAL. Mechanism confirmed in source; currently INERT (see caveat)
- **Severity**: High IF the branch existed and the tool is remotely callable

## Summary
`update_server` takes no arguments and no auth. It runs, in sequence,
`git pull origin future-testing`, `npm install`, `npm run build`, then the
server respawns onto the new build. Any MCP client able to call the tool can
make the server fetch and execute code from a hardcoded branch and rebuild
itself.

## Affected code
`src/modules/updater/index.ts`
```js
const steps = [
  { name: 'git pull',   cmd: 'git', args: ['pull', 'origin', 'future-testing'] },
  { name: 'npm install',cmd: 'npm', args: ['install'] },
  { name: 'npm run build', cmd: 'npm', args: ['run', 'build'] },
];
for (const step of steps) { await execAsync(step.cmd, step.args, INSTALL_ROOT); }
```
Tool declared at `src/modules/api-integration/tool-definition/index.ts:638`
("Pull the latest changes from GitHub and rebuild the server ...").

## Caveat (why POTENTIAL, not CONFIRMED)
The branch `future-testing` does not exist on origin (only `main`). In the
current state `git pull` fails after ~2s and no update occurs — the target
stayed on its pinned commit and node_modules was untouched during fuzzing.
The risk is latent: if that branch is created, or an attacker can influence the
git remote/branch, the tool becomes a remote code-execution-on-update
primitive. Even inert, an unauthenticated tool that shells out to
git/npm on every call is a design concern.

## Suggested fix
Require explicit authorization for `update_server`; pin/verify the update
source; do not expose self-update over the same untrusted tool channel.
