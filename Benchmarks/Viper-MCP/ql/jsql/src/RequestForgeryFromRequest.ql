/**
 * @name Server-side request forgery (MCP request -> outbound request)
 * @description Detects externally controlled data flowing into outbound
 *              request targets. In addition to standard sources, this query
 *              explicitly treats the request parameter of an MCP
 *              setRequestHandler callback as a source. To reduce false
 *              positives from fixed-base URLs plus user-controlled path or
 *              query suffixes, it only keeps flows where user input can still
 *              influence target-locating components such as the hostname or scheme.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id js/request-forgery-from-request
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import McpRequestForgeryConfig
import McpRequestForgeryFlow::PathGraph

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
  McpRequestForgeryFlow::PathNode srcNode, McpRequestForgeryFlow::PathNode dstNode, int steps
) {
  steps = 0 and srcNode = dstNode
  or
  steps > 0 and steps <= 25 and
  exists(McpRequestForgeryFlow::PathNode mid, int prev |
    prev = steps - 1 and
    srcNode.getASuccessor() = mid and
    reachesInSteps(mid, dstNode, prev)
  )
}

private predicate nodeOnFlowPathWithDistance(
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink,
  McpRequestForgeryFlow::PathNode n, int d
) {
  d >= 0 and d <= 25 and
  reachesInSteps(source, n, d) and
  exists(int rem |
    rem >= 0 and rem <= 25 and
    reachesInSteps(n, sink, rem)
  )
}

private string oneFunctionAtDistance(
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink, int d
) {
  result =
    min(string fn |
      exists(McpRequestForgeryFlow::PathNode n |
        nodeOnFlowPathWithDistance(source, sink, n, d) and
        nodeFunctionDisplay(n.getNode(), fn)
      )
    )
}

private predicate hasFunctionAtDistance(
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink, int d
) {
  exists(string fn | fn = oneFunctionAtDistance(source, sink, d))
}

private int previousDistanceWithFunction(
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink, int d
) {
  d in [0 .. 25] and
  result = max(int p | p >= 0 and p < d and hasFunctionAtDistance(source, sink, p))
}

private predicate isDisplayedDistance(
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink, int d
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
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink
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

from
  McpRequestForgeryFlow::PathNode source, McpRequestForgeryFlow::PathNode sink,
  DataFlow::Node request, string kind, DataFlow::Node highlight
where
  McpRequestForgeryFlow::flowPath(source, sink) and
  isAnyRequestForgerySinkWithHighlight(sink.getNode(), request, kind, highlight)
select
  highlight, source, sink,
  "Data flow (functions): " + detailedFunctionChain(source, sink) +
    ". SSRF risk: user-controlled input can influence the " + kind +
    " that determines where this request is sent."
