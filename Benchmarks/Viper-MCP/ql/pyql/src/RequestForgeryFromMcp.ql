/**
 * @name Full server-side request forgery (MCP tool input)
 * @description Making a network request to a URL that is fully controlled by
 *              MCP tool input or other external data allows request forgery attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id py/mcp-full-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.Concepts
import McpPyRequestForgeryConfig
import McpPyServerSideRequestForgeryFlow::PathGraph

from
  McpPyServerSideRequestForgeryFlow::PathNode source,
  McpPyServerSideRequestForgeryFlow::PathNode sink, Http::Client::Request request
where
  request = sink.getNode().(ServerSideRequestForgery::Sink).getRequest() and
  McpPyServerSideRequestForgeryFlow::flowPath(source, sink) and
  fullyControlledRequest(request)
select request, source, sink,
  "The full URL of this request depends on a $@.",
  source.getNode(),
  "user-provided value"
