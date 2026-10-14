# Missing output encoding in `calculator`: a string literal in `expression` is returned unchanged as the result

**Repository:** `armorwallet/armor-crypto-mcp` · **Tool:** `calculator` · **Tested commit:** `c026c00`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`calculator` evaluates a math expression with a small AST walker and returns `{"result": ...}`. The walker accepts any `ast.Constant`, so an expression that is just a string literal evaluates to that string. The string is returned as the result with no encoding. Markup in the string comes back unchanged. The output is plain JSON text, so the impact is low. The underlying gap is that a calculator accepts non-numeric constants at all.

## Details
The tool, `armor_crypto_mcp/armor_mcp.py:100-110`, returns `{'result': calculate(expression, variables)}`. The evaluator, `armor_crypto_mcp/armor_client.py:762-766` and `:787-788`:

```python
    def _eval(node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Constant):  # Python 3.8+
            return node.value
...
    parsed = ast.parse(expr, mode="eval")
    return _eval(parsed.body)
```

`ast.Constant` covers strings, bytes, `None` and `Ellipsis` as well as numbers. A quoted string in `expression` is therefore returned unchanged. String constants also flow into the allowed operators, since `ast.Mult` accepts `str * int`.

## Steps to reproduce
1. Prerequisites: Python 3.11 or newer (`pyproject.toml:6`). `ARMOR_API_KEY` is not needed for `calculator`.
2. Install and start the server. The README configures it as `uvx armor-crypto-mcp@latest`. To test the tested commit, run `pip install .` in a checkout at `c026c00`, which installs the `armor-crypto-mcp` entry point.
3. Call the tool:

   ```json
   {"expression": "\"<b>tofu-poc</b>\"", "variables": {}}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="armor-crypto-mcp", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("calculator", {"expression": "\"<b>tofu-poc</b>\"", "variables": {}})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is a JSON object whose `result` is the string `<b>tofu-poc</b>`, with the markup unchanged.

## Expected behavior
The calculator accepts only numeric constants (and lists of numbers), and rejects string or bytes literals with a clear error.

## Actual behavior
String literals are returned as results. From the fuzzing run:

```
input:  {'expression': '"eprxx{{p$e"', 'variables': {}}
output: '{\n  "result": "eprxx{{p$e"\n}'
```

## Impact
The model chooses the expression, and prompt injection in untrusted content can steer it. The echoed value sits in a JSON string in plain-text MCP output. It matters only if a client renders tool output as HTML, and the caller could have written the same text directly. Low severity.

## Suggested fix
- In `_eval`, accept `ast.Constant` only when `type(node.value) in (int, float)` (excluding `bool` if needed). Raise `TypeError` for anything else.
- Drop the `ast.Num` branch. It is deprecated and redundant with `ast.Constant`.

## Status on the default branch
Still present at `c026c00` (2025-05-27). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 1 issues and 26 pull requests (fetched 2026-10-01) and the README / README_prompts on the default branch. The README lists the tool only as "Statistical Calculator for accurate Analysis" and says nothing about accepted input.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on `{{`. `check_introspection_divide_by_zero` and `check_introspection_type_confusion` also fired for this tool.
- Campaigns and executions: `corpus-sbx`, 3072 executions, 74 successful, 60 s budget. Most fuzz inputs are not valid Python expressions, so most calls raise.
- Evidence (verbatim): input `{'expression': '"eprxx{{p$e"', 'variables': {}}`, output `'{\n  "result": "eprxx{{p$e"\n}'`.
- Hand-check hints: **weak**. A string constant is evaluated and returned. That is a correctness bug in a calculator, not meaningful XSS: the output is JSON in plain text, and `{{` is only braces. I would not file this as a security issue.
- More useful observation (code reading only, not run, not ToFu's finding): the walker allows `ast.Pow` and `ast.Mult` on unbounded values. An expression like `9**9**9` (huge integer) or `"a"*10**9` (string constant times a large int) should exhaust CPU or memory in the server process (CWE-400). If anything here is filed, that is the better candidate. Bounding exponent and operand sizes and rejecting non-numeric constants fixes both.
</details>
