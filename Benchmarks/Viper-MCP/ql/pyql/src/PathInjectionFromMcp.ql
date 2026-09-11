/**
 * @name Uncontrolled data used in file system path (MCP tool input)
 * @description Accessing paths influenced by MCP tool input or other external data
 *              can allow a malicious client to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/mcp-path-injection
 * @tags correctness
 *       security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import python
import McpPyPathInjectionConfig
import McpPyPathInjectionFlow::PathGraph

from McpPyPathInjectionFlow::PathNode source, McpPyPathInjectionFlow::PathNode sink
where McpPyPathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This path depends on a $@.",
  source.getNode(),
  "user-provided value"
