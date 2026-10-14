import javascript
import semmle.javascript.security.dataflow.RequestForgeryCustomizations
import semmle.javascript.security.dataflow.RequestForgeryQuery
import semmle.javascript.security.dataflow.UrlConcatenation

predicate mcpRequestHandlerParamSource(DataFlow::Node n) {
  exists(DataFlow::InvokeNode call, DataFlow::FunctionNode handler |
    call.getCalleeName() = "setRequestHandler" and
    call.getArgument(1) = handler and
    handler.getParameter(0) = n
  )
}

predicate isAdditionalRequestForgerySinkWithHighlight(
  DataFlow::Node sink, DataFlow::Node request, string kind, DataFlow::Node highlight
) {
  exists(DataFlow::InvokeNode call, string name |
    sink = call.getArgument(0) and
    request = sink and
    highlight = sink and
    kind = "URL" and
    name = call.getCalleeName() and
    name in [
      "fetch", "request", "axios", "got",
      "httpRequest", "httpsRequest", "doRequest",
      "open", "openUrl", "openURL"
    ]
  )
}

predicate isAnyRequestForgerySinkWithHighlight(
  DataFlow::Node sink, DataFlow::Node request, string kind, DataFlow::Node highlight
) {
  sink instanceof RequestForgery::Sink and
  request = sink.(RequestForgery::Sink).getARequest() and
  kind = sink.(RequestForgery::Sink).getKind() and
  highlight = request
  or
  isAdditionalRequestForgerySinkWithHighlight(sink, request, kind, highlight)
}

predicate isAnyRequestForgerySink(DataFlow::Node sink) {
  exists(DataFlow::Node request, string kind, DataFlow::Node highlight |
    isAnyRequestForgerySinkWithHighlight(sink, request, kind, highlight)
  )
}

module McpRequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(RequestForgery::Source).isServerSide()
    or
    mcpRequestHandlerParamSource(source)
  }

  predicate isSink(DataFlow::Node sink) { isAnyRequestForgerySink(sink) }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof RequestForgery::Sanitizer
    or
    node = HostnameSanitizerGuard::getABarrierNode()
  }

  predicate isBarrierOut(DataFlow::Node node) { hostnameSanitizingPrefixEdge(node, _) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    isAdditionalRequestForgeryStep(node1, node2)
  }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    exists(DataFlow::Node request, string kind, DataFlow::Node highlight |
      isAnyRequestForgerySinkWithHighlight(sink, request, kind, highlight) and
      result = highlight.getLocation()
    )
  }
}

module McpRequestForgeryFlow = TaintTracking::Global<McpRequestForgeryConfig>;
