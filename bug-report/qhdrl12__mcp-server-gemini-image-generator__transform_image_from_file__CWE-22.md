# Path traversal in `transform_image_from_file`: any path is opened, and images anywhere on disk are sent to Gemini

**Repository:** `qhdrl12/mcp-server-gemini-image-generator` · **Tool:** `transform_image_from_file` · **Tested commit:** `398037c`
**Weakness:** CWE-22 Path Traversal

## Summary
`transform_image_from_file` takes `image_file_path`, opens that file with Pillow, and sends the image plus a prompt to Gemini. The result is saved under `OUTPUT_IMAGE_PATH`. The path is not restricted to any directory: absolute paths and `../` are accepted. Two effects follow. Any image the user can read, such as screenshots, photos or scanned documents, can be uploaded to Gemini and re-saved by a steered call. The error messages also differ between "file not found" and "not an image", so any path's existence can be probed. Non-image files such as `/etc/passwd` are opened but rejected by Pillow, so their contents are not returned.

## Details
`src/mcp_server_gemini_image_generator/server.py:311-346` at `398037c`:

```python
@mcp.tool()
async def transform_image_from_file(image_file_path: str, prompt: str, model: str = "gemini-3-pro-image-preview") -> str:
    ...
        # Validate file path
        if not os.path.exists(image_file_path):
            raise ValueError(f"Image file not found: {image_file_path}")

        # Translate the prompt to English
        translated_prompt = await translate_prompt(prompt)

        # Load the source image directly using PIL
        try:
            source_image = PIL.Image.open(image_file_path)
        ...
        _, path = await process_image_transform(source_image, translated_prompt, prompt, model=model)
```

- The only check is `os.path.exists`. There is no base directory and no `realpath` containment.
- `process_image_transform` sends the opened image to Gemini (`server.py:185-210`). `save_image` writes the result to `OUTPUT_IMAGE_PATH` and calls `image.show()` (`utils.py:39-61`).
- A missing file returns `Image file not found: <path>`. An existing non-image returns `Could not identify image format...` (`server.py:338-340`). That difference is an existence oracle. `translate_prompt` swallows Gemini errors (`server.py:144-147`), so the oracle works even without a valid API key.

## Steps to reproduce
1. Prerequisites: Python 3.11+ (`requires-python = ">=3.11"`), `uv`, and a Linux host for `/etc/hostname` (on macOS use any other existing text file). The existence probe needs no working `GEMINI_API_KEY`. The upload case needs a valid one.
2. Install and start the server:
   ```
   git clone https://github.com/qhdrl12/mcp-server-gemini-image-generator.git
   cd mcp-server-gemini-image-generator && git checkout 398037c39eae698f3cb0b306a7206746931d146e
   uv venv && uv pip install -e .
   GEMINI_API_KEY=<key-or-dummy> OUTPUT_IMAGE_PATH=/tmp/tofu-poc-out uv run mcp-server-gemini-image-generator
   ```
3. Call the tool, first on a file that exists but is not an image, then on a path that does not exist:
   ```json
   {"image_file_path": "/etc/hostname", "prompt": "tofu-poc", "model": "gemini-3-pro-image-preview"}
   {"image_file_path": "/etc/tofu-poc-does-not-exist", "prompt": "tofu-poc", "model": "gemini-3-pro-image-preview"}
   ```

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["--directory", "/absolute/path/to/mcp-server-gemini-image-generator", "run", "mcp-server-gemini-image-generator"],
           env={"GEMINI_API_KEY": "dummy", "OUTPUT_IMAGE_PATH": "/tmp/tofu-poc-out", "PATH": os.environ["PATH"]},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for p in ["/etc/hostname", "/etc/tofu-poc-does-not-exist"]:
                   result = await session.call_tool("transform_image_from_file", {"image_file_path": p, "prompt": "tofu-poc", "model": "gemini-3-pro-image-preview"})
                   print(result)

   asyncio.run(main())
   ```
   Relative traversal (`../../../../etc/hostname`) is accepted as well; it resolves against the server's working directory. To see an out-of-tree image uploaded, set a real key and pass the path of any PNG outside the project, for example `/tmp/tofu-poc.png`.
4. What to observe: the first call returns `Error transforming image: Could not identify image format. Supported formats include PNG, JPEG, GIF, WebP.`, so the file exists. The second returns `Error transforming image: Image file not found: /etc/tofu-poc-does-not-exist`. With a real key and an image path, the image is sent to Gemini and a transformed copy appears in `/tmp/tofu-poc-out`.

## Expected behavior
The tool should read only from a configured input directory and reject paths that resolve outside it. It should return the same generic error for "missing" and "not an image".

## Actual behavior
Any path is opened. From the fuzzing run:

```
input:  {'image_file_path': '../../../../etc/passwd', 'prompt': 'Make the image brighter', ...}
output: Error transforming image: Could not identify image format. Supported formats include PNG, JPEG, GIF, WebP.

input:  {'image_file_path': '..\\..\\..\\..\\windows\\win.ini', 'prompt': 'Add a blue filter', ...}
output: Error transforming image: Image file not found: ..\..\..\..\windows\win.ini
```

ToFu's runtime tracer confirmed that `../../../../etc/passwd` was opened by the server process.

## Impact
In MCP the LLM picks `image_file_path`, and prompt injection can steer it. A steered call can probe whether arbitrary paths exist. It can also make the server upload any readable image, including private photos, screenshots or ID scans, to Gemini under the user's API key, and keep a transformed copy on disk. Non-image files are not disclosed, so this is a moderate privacy issue rather than an arbitrary file read.

## Suggested fix
- Add an input root, for example `INPUT_IMAGE_PATH`, falling back to `OUTPUT_IMAGE_PATH`. Resolve with `os.path.realpath` and reject unless `os.path.commonpath([root, target]) == root`.
- Return one generic error for missing, unreadable and non-image files, and do not echo the path.
- Optionally check the extension, and open with `PIL.Image.open(...).verify()` before any API call. Move `translate_prompt` after the image check so invalid input does not spend a Gemini call.

## Status on the default branch
Still present at `398037c` (2026-03-16). The tested commit is the head of the default branch.

## Prior reports
- #6 "fix: support Gemini 3 Pro and fix serialization error" (PR, closed 2026-03-15; its merge commit is the tested head `398037c`): the newest PR. It adds the `model` parameter to the image and transform tools, including this one. Its body says nothing about path checks. Does not fix this.
- Documentation: README.md, `transform_image_from_file`: "`image_file_path`: Path to the image file to be transformed". The tool is documented as taking a caller-chosen path with no input directory or restriction, so a maintainer may treat reading any path as intended. No README text warns about untrusted paths or uploads of local images to Gemini.
- No issue or PR reports this. Searched the 1 issue and all 5 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`. On the `../../../../etc/passwd` call, `check_introspection_sensitive_file_access` and `check_file_access` also fired (a real open was observed). The tool's trigger list also includes `check_introspection_log_injection` (the prompt and path are logged raw at `server.py:324-325`) and `check_reflected_output` (the path is echoed in the error).
- Campaigns and executions: corpus-sbx 2,560 exec / 2,549 ok (60 s). e2-0922 512 / 506 (60 s).
- Evidence (verbatim, trimmed):
  - `{'image_file_path': '/etc/passwd\x00', 'prompt': 'Invert the colors', 'model': 'gemini-3-pro-image-preview'}` -> `'Error transforming image: Image file not found: /etc/passwd\x00'`. `os.path.exists` returns False on an embedded NUL.
  - `{'image_file_path': '../../../../etc/passwd', 'prompt': 'Make the image brighter', ...}` -> `'Error transforming image: Could not identify image format. Supported formats include PNG, JPEG, GIF, WebP.'`; analysis: `Access to sensitive file ... '../../../../etc/passwd' (Matched pattern: '/etc/passwd')`.
  - `{'image_file_path': '..\\..\\..\\..\\windows\\win.ini', ...}` -> `'Error transforming image: Image file not found: ..\\..\\..\\..\\windows\\win.ini'`.
- Hand-check hints: real but limited. The caller path reaches `PIL.Image.open` unchecked, and the open was observed at runtime. Pillow rejects non-images, so there is no content disclosure for text files. The concrete effects are the existence oracle (seen in the logs) and the upload of arbitrary readable images to Gemini (from the code, not exercised: the fuzz run had no working key). The tool is designed to take user file paths, so a maintainer may see this as intended. The argument for a fix is the prompt-injection steering. The claim that the oracle works without a key rests on `translate_prompt` catching the missing-key error; that is from reading the code.
</details>
