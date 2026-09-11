# Why this is here

The three alert-bearing runs from the 13:22 campaign. 423 raw alerts between
them. ALL are false positives, from two distinct defects found by triaging
them. Kept because they are the evidence for both.

## weread::get_book_best_reviews (334 alerts, check_invalid_json)
## weread::search_books           (70 alerts, check_log_injection)

The server has no WeRead cookie configured and answers EVERY input with a
NORMAL MCP result whose payload is an error object:

    Tool Output : {'error': {'message': '没有找到cookie，请按照文档填写cookie或配置Cookie Cloud'}}

It never set isError, so the runner scored every call a success: the tool
looked 100% executable (n_success == n_exec) and the outcome oracle concluded
it "executed successfully without raising" for inputs the sanitizers had
flagged. The tool never ran its own logic at all. FIXED: JSRunner now treats a
top-level truthy `error`/`errors` member as a failed execution
(sec4_design.tex:270 -- the oracle evaluates "structured error types").

## bing-cn::crawl_webpage (19 alerts, 4 signatures)

check_strict_url_security_contract read generated_arguments["url"] literally.
It was written for targets/fuzz_http_check.py, whose argument IS called url.
crawl_webpage's argument is `urlMap`, so url_input was None and every sub-check
fired on None:

    Violations: [Raw Input Error: Expected str type, got NoneType |
                 Structure Error: Missing scheme | Canonicalization Error:
                 Hostname is empty | SSRF Check Error: Empty hostname]
    Input: 'None'

FIXED: it now locates the URL argument whatever it is called (string, list, or
map values) and returns False when the tool has no URL argument at all.

## Worth re-running, not dismissing

With the fix, `urlMap: {"u": "http://10.0.0.1/internal_api"}` fires for the
right reason -- and the log shows the tool DID attempt that fetch, returning
"抓取网页失败: 无法连接到服务器". A tool that accepts an RFC1918 destination and
tries to reach it is the SSRF shape ToFu exists to find. Re-run crawl_webpage
before drawing any conclusion.

## Still unresolved (see nazmul.todo)

- check_resource_exhaustion fired at 5.01s against a 2.0s limit on a
  WEB-CRAWLING tool. A network fetch taking 5s is normal; the limit needs to be
  per-tool or network tools need exclusion.
- check_process_and_fd_leaks reported "PID 60149 (node)" while two workers were
  running concurrently. Likely the other worker's server; the ancestor filter
  needs checking under parallelism.
