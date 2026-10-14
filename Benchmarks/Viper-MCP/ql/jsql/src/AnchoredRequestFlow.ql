/**
 * @name Anchored outbound request flow
 * @description Emits MCP-tainted outbound request flows with source/sink
 *              locations, enclosing functions, and request-target kind.
 *              This query is consumed by src/codeql/anchored_evidence.py and
 *              is intentionally table-only.
 * @kind table
 * @id js/mcp-anchored-request-flow
 */

import javascript
import McpRequestForgeryConfig

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
  McpRequestForgeryFlow::PathNode source,
  McpRequestForgeryFlow::PathNode sink,
  DataFlow::Node request,
  string kind,
  DataFlow::Node highlight
where
  McpRequestForgeryFlow::flowPath(source, sink) and
  isAnyRequestForgerySinkWithHighlight(sink.getNode(), request, kind, highlight) and
  exists(source.getNode().getFile()) and
  exists(highlight.getFile())
select
  source.getNode().getFile().getRelativePath(),
  source.getNode().getStartLine(),
  highlight.getFile().getRelativePath(),
  highlight.getStartLine(),
  nodeFunctionDisplay(source.getNode()),
  nodeFunctionDisplay(sink.getNode()),
  kind
