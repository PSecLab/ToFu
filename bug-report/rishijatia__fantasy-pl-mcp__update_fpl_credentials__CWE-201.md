# `update_fpl_credentials` writes the caller's token over the stored credentials before validating it, then sends it out

**Repository:** `rishijatia/fantasy-pl-mcp` · **Tool:** `update_fpl_credentials` · **Tested commit:** `fdaef00`
**Weakness:** CWE-201 Insertion of Sensitive Information Into Sent Data

## Summary
`update_fpl_credentials` stores a new FPL OIDC refresh token and checks it by exchanging it at the FPL token endpoint. In one call, the tool writes `~/.fpl-mcp/credentials.enc`, reads it back, and posts the token over the network. ToFu flagged this read-then-send pattern. The destination is the fixed `FPL_TOKEN_URL`, so the token does not go to a host the caller picks. The concrete problem is ordering: the new value is written to the credential store before it is validated. Any call with a bad value therefore replaces a working stored token.

## Details
`src/fpl_mcp/fpl/tools/team.py:440-468` at `fdaef00`:

```python
        token = extract_refresh_token(refresh_token)
        ...
        auth_manager = get_auth_manager()
        team_id = team_id.strip() or auth_manager.team_id
        ...
        auth_manager.set_credentials(token, str(team_id))

        # Validate immediately: the exchange claims the token before the user's
        # browser can rotate it away, and /my-team/ proves the API accepts it.
        try:
            team_data = await auth_manager.get_my_team()
        except Exception as e:
            return {
                "updated": False,
                "error": f"Token was stored but failed validation: {e}. Ask the "
```

- `set_credentials` (`src/fpl_mcp/fpl/auth_manager.py:47-51`) encrypts and writes the new token to `credentials.enc` right away.
- `get_my_team` triggers `_authenticate`, which POSTs the token to `FPL_TOKEN_URL` (`auth_manager.py:93-103`; the default is `https://account.premierleague.com/as/token`, `config.py:34-35`). On a 400 or 401 it reloads `credentials.enc` (`auth_manager.py:132`). That reload is the read ToFu saw. By then the store holds the same bad token, so the previous good token is already gone.
- `team_id` is any string. It goes into the URL path unchecked: `f"{FPL_API_BASE_URL}/my-team/{team_id}/"` (`auth_manager.py:227`).

## Steps to reproduce
1. Prerequisites: Python 3.10 or later and outbound access to `account.premierleague.com`. Use a throwaway home directory so your real credentials are not overwritten: `mkdir -p /tmp/tofu-fpl-home`. Optionally, run `HOME=/tmp/tofu-fpl-home fpl-mcp-config setup` with a valid token first, so you can watch it get replaced.
2. Install and start the server:
   ```
   pip install "git+https://github.com/rishijatia/fantasy-pl-mcp.git@fdaef005143347455fc500cb1f934d451f95251a"
   HOME=/tmp/tofu-fpl-home python -m fpl_mcp
   ```
3. Call the tool with these arguments:
   ```json
   {"refresh_token": "tofu-poc-invalid-token", "team_id": "1"}
   ```

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="python", args=["-m", "fpl_mcp"],
           env={"HOME": "/tmp/tofu-fpl-home", "PATH": os.environ["PATH"]},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("update_fpl_credentials", {"refresh_token": "tofu-poc-invalid-token", "team_id": "1"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe:
   - The result is `{"updated": false, "error": "Token was stored but failed validation: FPL refresh token is invalid or expired. ..."}`.
   - `/tmp/tofu-fpl-home/.fpl-mcp/credentials.enc` has a new modification time and now holds the bogus token. After this, `HOME=/tmp/tofu-fpl-home fpl-mcp-config test` fails even if a valid token was stored before.
   - One POST to the FPL token endpoint carries the supplied token.

## Expected behavior
The tool should exchange the candidate token first and persist it only if the exchange succeeds. If it fails, the previously stored credentials should stay untouched. `team_id` should be rejected unless it is numeric.

## Actual behavior
The unvalidated token is persisted first, and the error message says so. From the fuzzing run:

```
{"updated": false, "error": "Token was stored but failed validation: FPL refresh token is invalid or expired. ... (Failed to decode refresh token (Correlation ID: ...)). Ask the user to copy a fresh oidc.user value and try again."}
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. A steered call with any string wipes the user's working FPL session, and the user has to run setup again. A steered call with a valid token from the attacker's own FPL account would make later authenticated calls run against that account. The stored token is not sent to an attacker-chosen host, so this is not a credential leak. Severity is low.

## Suggested fix
- Validate before storing. Run the refresh-token exchange on the candidate token the same way `_authenticate` does, keeping it in memory only. Call `store_credentials` only after the exchange succeeds, and store the rotated token it returns. On failure, keep the old in-memory and on-disk credentials.
- Validate `team_id` (`team_id.isdigit()`) before using it in a URL.

## Status on the default branch
Still present at `fdaef00` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
- #22 "Fix authentication: migrate to PingOne OIDC refresh-token flow" (PR, merged/closed 2026-07-31): introduced `update_fpl_credentials`; its description says the tool "stores and validates" a pasted token, which is the store-before-validate order reported here. It does not discuss a failed validation replacing a working token, so it is the origin, not a fix.
- #31 "Support browser login flow when token expires" (PR, open 2026-09-23): no description, so I could not tell whether it changes `update_fpl_credentials`. Check its diff before filing.
- Documentation: `README.md`: "`update_fpl_credentials` - Update your stored FPL credentials from within a chat" (documents that a chat call may replace the stored credentials by design; says nothing about validating first). No SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: data-exfiltration via `check_introspection_exfil`. The tool also triggered `check_invalid_json` and `check_resource_exhaustion`, which I did not examine.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok (60 s). repo24-b 1,536 / 1,520 (4200 s). The corpus-sbx exec record says 1 execution, yet three distinct corpus-sbx evidence calls are listed. Check the log before quoting numbers.
- Evidence (verbatim, trimmed):
  - input `{'refresh_token': '"refresh_token": "", "team_id": "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini', 'team_id': '..\\..\\..\\..\\windows\\win.ini'}` -> `{"updated": false, "error": "Token was stored but failed validation: FPL refresh token is invalid or expired. ... (Failed to decode refresh token (Correlation ID: a47b...))..."}`.
  - analysis: `tool READ sensitive/traversal file(s) ['/home/mza6485/.tofu_scratch/rishijatia__fantasy-pl-mcp__update_fpl_credentials/home/.fpl-mcp/credentials.enc' x2] AND made outbound network connection(s) to ['130.250.137.171']`.
- Hand-check hints: weak, and likely a false positive as CWE-201. The file read is the server's own credential store, under the sandboxed HOME. The send goes to the hard-coded OIDC token endpoint, and the data sent is the caller's own token. I did not verify that 130.250.137.171 is `account.premierleague.com` (no network here). The store-before-validate ordering is real, from reading the code: `team.py:457` stores the token before `team.py:462` validates it, and the error text confirms it. It is a low-severity integrity/DoS issue rather than exfiltration. If you file it, consider retitling it as a logic bug and dropping the CWE-201 label. The `win.ini` strings in `team_id` reach only the URL path on the fixed FPL host, and only after authentication succeeds (not reached in these runs).
</details>
