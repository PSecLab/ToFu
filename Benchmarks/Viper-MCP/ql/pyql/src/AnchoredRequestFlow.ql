/**
 * @name Anchored Python request flow
 * @description Emits MCP-tainted Python server-side request forgery flows with
 *              source/request locations. This query is consumed by
 *              src/codeql/anchored_evidence.py and is intentionally table-only.
 * @kind table
 * @id py/mcp-anchored-request-flow
 */

import python
import semmle.python.Concepts
import McpPyRequestForgeryConfig

from
  McpPyServerSideRequestForgeryFlow::PathNode source,
  McpPyServerSideRequestForgeryFlow::PathNode sink,
  Http::Client::Request request
where
  request = sink.getNode().(ServerSideRequestForgery::Sink).getRequest() and
  McpPyServerSideRequestForgeryFlow::flowPath(source, sink) and
  fullyControlledRequest(request) and
  exists(source.getNode().getLocation().getFile()) and
  exists(request.getLocation().getFile())
select
  source.getNode().getLocation().getFile().getRelativePath(),
  source.getNode().getLocation().getStartLine(),
  request.getLocation().getFile().getRelativePath(),
  request.getLocation().getStartLine(),
  "request"
