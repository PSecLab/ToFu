/**
 * @name Anchored Python path flow
 * @description Emits MCP-tainted Python file/path flows with source/sink
 *              locations. This query is consumed by
 *              src/codeql/anchored_evidence.py and is intentionally table-only.
 * @kind table
 * @id py/mcp-anchored-path-flow
 */

import python
import McpPyPathInjectionConfig

from
  McpPyPathInjectionFlow::PathNode source,
  McpPyPathInjectionFlow::PathNode sink
where
  McpPyPathInjectionFlow::flowPath(source, sink) and
  exists(source.getNode().getLocation().getFile()) and
  exists(sink.getNode().getLocation().getFile())
select
  source.getNode().getLocation().getFile().getRelativePath(),
  source.getNode().getLocation().getStartLine(),
  sink.getNode().getLocation().getFile().getRelativePath(),
  sink.getNode().getLocation().getStartLine(),
  "path"
