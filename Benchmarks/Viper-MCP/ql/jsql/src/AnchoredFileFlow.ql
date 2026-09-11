/**
 * @name Anchored file access flow
 * @description Emits MCP-tainted file path flows with source/sink locations,
 *              enclosing functions, and access kind. This query is consumed by
 *              src/codeql/anchored_evidence.py and is intentionally table-only.
 * @kind table
 * @id js/mcp-anchored-file-flow
 */

import javascript
import McpTaintedPathConfig

private string nodeFunctionDisplay(DataFlow::Node n) {
  exists(Function f |
    f = n.getContainer() and
    result = f.describe()
  )
  or
  not exists(Function f | f = n.getContainer()) and
  result = "<top-level>"
}

from
  McpTaintedPathFlow::PathNode source,
  McpTaintedPathFlow::PathNode sink,
  string kind
where
  McpTaintedPathFlow::flowPath(source, sink) and
  isFileAccessSinkWithKind(sink.getNode(), kind) and
  exists(source.getNode().getFile()) and
  exists(sink.getNode().getFile())
select
  source.getNode().getFile().getRelativePath(),
  source.getNode().getStartLine(),
  sink.getNode().getFile().getRelativePath(),
  sink.getNode().getStartLine(),
  nodeFunctionDisplay(source.getNode()),
  nodeFunctionDisplay(sink.getNode()),
  kind
