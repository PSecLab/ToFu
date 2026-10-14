# Path traversal in `generate_image`: `file_name` and `save_folder` write outside the intended directory

**Repository:** `fengin/image-gen-server` · **Tool:** `generate_image` · **Tested commit:** `4ec89fe`
**Weakness:** CWE-22 Path Traversal

## Summary
`generate_image` downloads a generated image and saves it under a caller-supplied `save_folder` with a
caller-supplied `file_name`. `file_name` is documented as "no path", but it is joined to `save_folder` with
`os.path.join` and never reduced to a basename, so `../` in `file_name` escapes the target directory.
`save_folder` itself is an unvalidated absolute directory that the tool will create and write into. An
attacker-influenced call can write downloaded bytes to an arbitrary path the process can write to.

## Details
In `server.py`, after validation, the tool creates `save_folder` if missing and joins `file_name` onto it
(`server.py:150`):

```python
# 检查并创建保存目录
save_folder = save_folder or IMG_SAVA_FOLDER
if not os.path.exists(save_folder):
    os.makedirs(save_folder)                       # 158: creates any caller-named dir
# ...
for i, url in enumerate(image_urls):
    save_path = os.path.join(save_folder, file_name)   # 177: file_name not basename-constrained
    base_name, ext = os.path.splitext(save_path)
    if i > 0: save_path = f"{base_name}_{i}{ext}"
    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, "wb") as f:               # 185-186: write to escaped path
            f.write(response.content)
```

`os.path.join('/base', '../x')` yields `/x`, and `os.path.join('/base', '/abs')` yields `/abs`, so a
`file_name` such as `../escaped.jpg` writes outside `save_folder`. There is no `os.path.basename(file_name)`
and no check that `save_path` stays under `save_folder`. The tool description states `file_name` should not
contain a path, but nothing enforces it.

## Steps to reproduce
1. Prerequisites: Python 3.10+, `fastmcp`. Critically, a valid Jimeng (即梦) `sessionid` set as
   `JIMENG_API_TOKEN` in `server.py`; without it the upstream call returns a login error and nothing is
   downloaded or written (see Actual behavior).
2. Start the server: `uv run --with fastmcp fastmcp run /path/to/server.py`. Create a target root:
   `mkdir -p /tmp/tofu-poc/sub`.
3. Call the tool. Arguments as JSON:
   `{"prompt": "a small cat", "file_name": "../escaped.jpg", "save_folder": "/tmp/tofu-poc/sub"}`
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--with", "fastmcp", "fastmcp", "run", "/path/to/server.py"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generate_image", {
                   "prompt": "a small cat",
                   "file_name": "../escaped.jpg",
                   "save_folder": "/tmp/tofu-poc/sub"})
               print(result)

   asyncio.run(main())
   ```
4. With a working token, observe that the image is written to `/tmp/tofu-poc/escaped.jpg` - one level above
   the `save_folder` `/tmp/tofu-poc/sub` (`os.path.join('/tmp/tofu-poc/sub', '../escaped.jpg')` ->
   `/tmp/tofu-poc/escaped.jpg`). A deeper `../` chain, or an absolute `file_name`, reaches any writable path.

## Expected behavior
`file_name` should be reduced to a basename and the final `save_path` confirmed to stay under `save_folder`;
`save_folder` should be constrained to a configured output root.

## Actual behavior
In the fuzzing evidence the write did not occur because the upstream image service rejected the request:
`{"success": false, "error": "生成图片失败: [-2009] [请求jimeng失败]: check login error", "images": []}`
(no valid token), or the call was rejected for an empty `save_folder`:
`{"success": false, "error": "save_folder不能为空", "images": []}`.

## Impact
`file_name` and `save_folder` are chosen by the LLM and can be steered by prompt injection from untrusted
content. When the server is configured with a working Jimeng token (its normal operating state), a crafted
call writes attacker-chosen image bytes to a path outside the intended output directory, bounded by the
process's write permissions. Exploitation is gated on a successful upstream generation, so a server without
valid credentials cannot be made to write at all.

## Suggested fix
Use `file_name = os.path.basename(file_name)` and reject any remaining separators; resolve
`os.path.realpath(save_path)` and require it to start with `os.path.realpath(save_folder) + os.sep` before
`open(...,"wb")`. Constrain `save_folder` to a configured allow-listed root rather than `os.makedirs` on any
caller string.

## Status on the default branch
Still present at `4ec89fe` (2025-07-17). The current default branch head is the same commit that was tested;
`server.py` still joins `file_name` without basename reduction or containment.

## Prior reports
- #23 "在cherry studio中提示图片位置失败" (issue, closed 2025-07-09): the model sent the placeholder `"save_folder": "/path/to/save/folder"` and the server tried to create it (`[Errno 30] Read-only file system: '/path'`). This shows a model-chosen `save_folder` going straight to `os.makedirs`. It was reported as a usability bug, not a security one, and no check was added.
- #10 "图片生成目录不对" (issue, closed 2025-04-24): images were saved under `D:\path\to\save\folder`, the same placeholder path. Same cause, not a security report.
- #3 "自动传入项目图片地址" (issue, closed 2025-02-23): suggests rewording the `save_folder` docstring so the model passes the project's absolute image path on its own. A caller-chosen absolute `save_folder` is the intended use.
- Documentation: README.md: "file_name: 生成图片的文件名(不含路径，如果没有后缀则默认使用.jpg)" ("file name of the image, without a path") and "save_folder: 图片保存绝对地址目录" ("absolute directory to save the image in"). Writing to any absolute `save_folder` is documented by design. `file_name` is documented as path-free, but this is not enforced, so the `../` in `file_name` is the part that goes against the docs.
- No issue or PR reports `../` in `file_name`. Searched all 23 issues and 4 pull requests (fetched 2026-10-01) and README.md / proxy/README.md on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` fired. The tool also tripped
  `check_introspection_weak_hash` (MD5 in `proxy/jimeng`) and `check_resource_exhaustion` /
  `check_introspection_log_injection` - out of scope for this CWE-22 report.
- Campaigns and executions: corpus-sbx (2,048 / 1,998, 60s) and e2-0922 (512 / 494, 60s).
- Evidence (verbatim, trimmed): input `{'prompt': '正常风景图片', 'file_name': '..\\..\\..\\..\\windows\\win.ini',
  'save_folder': '/tmp', ...}` -> `check login error`. Other rows had empty `save_folder` -> rejected.
- Hand-check hints: REAL at code level but CONDITIONAL. `file_name` -> `os.path.join` -> `open(save_path,"wb")`
  with no basename reduction or containment (server.py:177, 185). The write only runs after
  `generate_images(...)` returns a non-empty URL list, which needs a valid 即梦 token; all evidence rows failed
  before the write (login error or empty save_folder), so none is a demonstrated escape. The evidence
  `file_name` uses Windows backslashes, which only traverse on Windows; the POSIX `../` payload in the repro
  is the portable case. Reproduction requires valid upstream credentials that we do not have; mark as
  verified-by-reading, not verified-by-run.
</details>
