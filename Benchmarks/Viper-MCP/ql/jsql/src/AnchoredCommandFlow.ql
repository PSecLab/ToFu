/**
 * @name Anchored command flow
 * @description Emits MCP-tainted command execution flows with source/sink
 *              locations and enclosing functions. This query is consumed by
 *              src/codeql/anchored_evidence.py and is intentionally table-only.
 * @kind table
 * @id js/mcp-anchored-command-flow
 */

import javascript
import McpCommandInjectionConfig

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
  McpCommandInjectionFlow::PathNode source,
  McpCommandInjectionFlow::PathNode sink,
  DataFlow::Node highlight
where
  McpCommandInjectionFlow::flowPath(source, sink) and
  (
    if isAnyCommandSinkWithHighlight(sink.getNode(), _)
    then isAnyCommandSinkWithHighlight(sink.getNode(), highlight)
    else highlight = sink.getNode()
  ) and
  exists(source.getNode().getFile()) and
  exists(highlight.getFile())
select
  source.getNode().getFile().getRelativePath(),
  source.getNode().getStartLine(),
  highlight.getFile().getRelativePath(),
  highlight.getStartLine(),
  nodeFunctionDisplay(source.getNode()),
  nodeFunctionDisplay(sink.getNode())
