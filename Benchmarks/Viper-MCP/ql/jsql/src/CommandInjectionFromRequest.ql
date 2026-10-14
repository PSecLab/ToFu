/**
 * @name Command injection (HTTP response / MCP stdio -> exec)
 * @description Detects command-execution flows from externally controlled data.
 *              In addition to standard sources such as HTTP responses and user
 *              input, this query explicitly treats the request parameter of an
 *              MCP setRequestHandler callback as a source so it can identify
 *              cases where stdio-delivered MCP arguments flow directly into exec.
 * @kind path-problem
 * @problem.severity error
 * @id js/command-injection-from-request
 * @tags security
 *       external/cwe/cwe-078
 */

import javascript
import McpCommandInjectionConfig
import McpCommandInjectionFlow::PathGraph
import semmle.javascript.security.dataflow.CommandInjectionQuery

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
  McpCommandInjectionFlow::PathNode srcNode, McpCommandInjectionFlow::PathNode dstNode, int steps
) {
  steps = 0 and srcNode = dstNode
  or
  steps > 0 and steps <= 25 and
  exists(McpCommandInjectionFlow::PathNode mid, int prev |
    prev = steps - 1 and
    srcNode.getASuccessor() = mid and
    reachesInSteps(mid, dstNode, prev)
  )
}

private predicate nodeOnFlowPathWithDistance(
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink,
  McpCommandInjectionFlow::PathNode n, int d
) {
  d >= 0 and d <= 25 and
  reachesInSteps(source, n, d) and
  exists(int rem |
    rem >= 0 and rem <= 25 and
    reachesInSteps(n, sink, rem)
  )
}

private string oneFunctionAtDistance(
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink, int d
) {
  result =
    min(string fn |
      exists(McpCommandInjectionFlow::PathNode n |
        nodeOnFlowPathWithDistance(source, sink, n, d) and
        nodeFunctionDisplay(n.getNode(), fn)
      )
    )
}

private predicate hasFunctionAtDistance(
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink, int d
) {
  exists(string fn | fn = oneFunctionAtDistance(source, sink, d))
}

private int previousDistanceWithFunction(
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink, int d
) {
  d in [0 .. 25] and
  result = max(int p | p >= 0 and p < d and hasFunctionAtDistance(source, sink, p))
}

private predicate isDisplayedDistance(
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink, int d
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
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink
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
  McpCommandInjectionFlow::PathNode source, McpCommandInjectionFlow::PathNode sink,
  DataFlow::Node highlight
where
  McpCommandInjectionFlow::flowPath(source, sink) and
  (
    if isAnyCommandSinkWithHighlight(sink.getNode(), _)
    then isAnyCommandSinkWithHighlight(sink.getNode(), highlight)
    else highlight = sink.getNode()
  )
select
  highlight, source, sink,
  "Data flow (functions): " + detailedFunctionChain(source, sink) +
    ". This command line depends on a $@.",
  source.getNode(),
  "user- or server-provided value (including MCP request params)"
