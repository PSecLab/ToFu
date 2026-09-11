import javascript
import semmle.javascript.security.dataflow.CommandInjectionCustomizations
import semmle.javascript.security.dataflow.CommandInjectionQuery

predicate mcpRequestHandlerParamSource(DataFlow::Node n) {
  exists(DataFlow::InvokeNode call, DataFlow::FunctionNode handler |
    call.getCalleeName() = "setRequestHandler" and
    call.getArgument(1) = handler and
    handler.getParameter(0) = n
  )
}

predicate isAdditionalCommandSinkWithHighlight(DataFlow::Node sink, DataFlow::Node highlight) {
  exists(DataFlow::InvokeNode call, string name |
    sink = call.getArgument(0) and
    highlight = sink and
    name = call.getCalleeName() and
    name in [
      "exec", "execSync", "execFile", "execFileSync",
      "spawn", "spawnSync",
      "execa", "execaCommand", "execaCommandSync",
      "$", "system", "popen",
      "runCommand", "executeCommand"
    ]
  )
  or
  exists(DataFlow::InvokeNode call, string name |
    sink = call.getArgument(1) and
    highlight = sink and
    name = call.getCalleeName() and
    name in ["spawn", "spawnSync", "execa"]
  )
}

predicate isAnyCommandSinkWithHighlight(DataFlow::Node sink, DataFlow::Node highlight) {
  isSinkWithHighlight(sink, highlight)
  or
  isAdditionalCommandSinkWithHighlight(sink, highlight)
}

module McpCommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CommandInjection::Source
    or
    mcpRequestHandlerParamSource(source)
  }

  predicate isSink(DataFlow::Node sink) { isAnyCommandSinkWithHighlight(sink, _) }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CommandInjection::Sanitizer
  }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    exists(DataFlow::Node node |
      isAnyCommandSinkWithHighlight(sink, node) and
      result = node.getLocation()
    )
  }
}

module McpCommandInjectionFlow = TaintTracking::Global<McpCommandInjectionConfig>;
