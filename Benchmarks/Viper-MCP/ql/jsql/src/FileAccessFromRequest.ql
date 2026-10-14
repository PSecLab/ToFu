/**
 * @name Unauthorized file read/write (MCP request -> file system path)
 * @description Detects externally controlled data flowing into file-system
 *              paths. In addition to standard sources, this query explicitly
 *              treats the request parameter of an MCP setRequestHandler callback
 *              as a source so it can identify unauthorized read/write or
 *              arbitrary file-access behaviors in MCP servers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id js/file-access-from-request
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import javascript
import McpTaintedPathConfig
import McpTaintedPathFlow::PathGraph

private predicate nodeFunctionDisplay(DataFlow::Node n, string display) {
  exists(Expr e, Function f |
    e = n.asExpr() and
    f = e.getEnclosingFunction() and
    display = f.describe()
  )
  or
  exists(Expr e |
    e = n.asExpr() and
    not exists(Function f | f = e.getEnclosingFunction()) and
    display = "<top-level>"
  )
}

private predicate reachesInSteps(
  McpTaintedPathFlow::PathNode srcNode, McpTaintedPathFlow::PathNode dstNode, int steps
) {
  steps = 0 and srcNode = dstNode
  or
  steps > 0 and steps <= 25 and
  exists(McpTaintedPathFlow::PathNode mid, int prev |
    prev = steps - 1 and
    srcNode.getASuccessor() = mid and
    reachesInSteps(mid, dstNode, prev)
  )
}

private predicate nodeOnFlowPathWithDistance(
  McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink,
  McpTaintedPathFlow::PathNode n, int d
) {
  d >= 0 and d <= 25 and
  reachesInSteps(source, n, d) and
  exists(int rem |
    rem >= 0 and rem <= 25 and
    reachesInSteps(n, sink, rem)
  )
}

private string oneFunctionAtDistance(
  McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink, int d
) {
  result =
    min(string fn |
      exists(McpTaintedPathFlow::PathNode n |
        nodeOnFlowPathWithDistance(source, sink, n, d) and
        nodeFunctionDisplay(n.getNode(), fn)
      )
    )
}

private predicate hasFunctionAtDistance(
  McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink, int d
) {
  exists(string fn | fn = oneFunctionAtDistance(source, sink, d))
}

private int previousDistanceWithFunction(
  McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink, int d
) {
  d in [0 .. 25] and
  result = max(int p | p >= 0 and p < d and hasFunctionAtDistance(source, sink, p))
}

private predicate isDisplayedDistance(
  McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink, int d
) {
  hasFunctionAtDistance(source, sink, d) and
  (
    not exists(int p | p = previousDistanceWithFunction(source, sink, d))
    or
    exists(int p |
      p = previousDistanceWithFunction(source, sink, d) and
      oneFunctionAtDistance(source, sink, p) != oneFunctionAtDistance(source, sink, d)
    )
  )
}

private string detailedFunctionChain(
  McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink
) {
  exists(int d, string fn | d >= 0 and d <= 25 and fn = oneFunctionAtDistance(source, sink, d)) and
  result =
    strictconcat(int d |
      d >= 0 and d <= 25 and isDisplayedDistance(source, sink, d)
      |
      oneFunctionAtDistance(source, sink, d),
      " -> " order by d
    )
}

private string fileAccessKind(McpTaintedPathFlow::PathNode sink) {
  result = "read"
  and
  exists(FileSystemReadAccess access |
    sink.getNode() = access.getAPathArgument()
    or
    sink.getNode() = access.getRootPathArgument()
  )
  or
  result = "write"
  and
  exists(FileSystemWriteAccess access |
    sink.getNode() = access.getAPathArgument()
    or
    sink.getNode() = access.getRootPathArgument()
  )
  or
  result = "access"
  and
  exists(FileSystemAccess access |
    not access instanceof FileSystemReadAccess and
    not access instanceof FileSystemWriteAccess and
    (
      sink.getNode() = access.getAPathArgument()
      or
      sink.getNode() = access.getRootPathArgument()
    )
  )
}

from McpTaintedPathFlow::PathNode source, McpTaintedPathFlow::PathNode sink
where
  McpTaintedPathFlow::flowPath(source, sink) and
  exists(string kind | kind = fileAccessKind(sink))
select
  sink.getNode(), source, sink,
  "Data flow (functions): " + detailedFunctionChain(source, sink) +
    ". File system " + fileAccessKind(sink) + " path depends on a $@.",
  source.getNode(),
  "user- or server-provided value (including MCP request params)"
