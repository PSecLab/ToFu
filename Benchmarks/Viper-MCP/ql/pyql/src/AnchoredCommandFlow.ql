/**
 * @name Anchored Python command flow
 * @description Emits MCP-tainted Python command execution flows with
 *              source/sink locations. This query is consumed by
 *              src/codeql/anchored_evidence.py and is intentionally table-only.
 * @kind table
 * @id py/mcp-anchored-command-flow
 */

import python
import McpPyCommandInjectionConfig

from
  McpPyCommandInjectionFlow::PathNode source,
  McpPyCommandInjectionFlow::PathNode sink
where
  McpPyCommandInjectionFlow::flowPath(source, sink) and
  exists(source.getNode().getLocation().getFile()) and
  exists(sink.getNode().getLocation().getFile())
select
  source.getNode().getLocation().getFile().getRelativePath(),
  source.getNode().getLocation().getStartLine(),
  sink.getNode().getLocation().getFile().getRelativePath(),
  sink.getNode().getLocation().getStartLine(),
  "command"
