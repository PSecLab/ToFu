/**
 * @name Uncontrolled command line (MCP tool input)
 * @description Using MCP tool input or other externally controlled strings in a command line
 *              may allow a malicious client to change the meaning of the command.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @sub-severity high
 * @precision high
 * @id py/mcp-command-line-injection
 * @tags correctness
 *       security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import python
import McpPyCommandInjectionConfig
import McpPyCommandInjectionFlow::PathGraph

from McpPyCommandInjectionFlow::PathNode source, McpPyCommandInjectionFlow::PathNode sink
where McpPyCommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command line depends on a $@.",
  source.getNode(),
  "user-provided value"
