import javascript
import semmle.javascript.security.dataflow.TaintedPathCustomizations
import semmle.javascript.security.dataflow.TaintedPathQuery

predicate mcpRequestHandlerParamSource(DataFlow::Node n) {
  exists(DataFlow::InvokeNode call, DataFlow::FunctionNode handler |
    call.getCalleeName() = "setRequestHandler" and
    call.getArgument(1) = handler and
    handler.getParameter(0) = n
  )
}

predicate isFileAccessSinkWithKind(DataFlow::Node sink, string kind) {
  exists(FileSystemReadAccess access |
    (
      sink = access.getAPathArgument()
      or
      sink = access.getRootPathArgument()
    ) and
    kind = "read"
  )
  or
  exists(FileSystemWriteAccess access |
    (
      sink = access.getAPathArgument()
      or
      sink = access.getRootPathArgument()
    ) and
    kind = "write"
  )
  or
  exists(FileSystemAccess access |
    not access instanceof FileSystemReadAccess and
    not access instanceof FileSystemWriteAccess and
    (
      sink = access.getAPathArgument()
      or
      sink = access.getRootPathArgument()
    ) and
    kind = "access"
  )
}

predicate isAnyFileAccessSink(DataFlow::Node sink) {
  sink instanceof TaintedPath::FsPathSink and
  exists(string kind | isFileAccessSinkWithKind(sink, kind))
}

module McpTaintedPathConfig implements DataFlow::StateConfigSig {
  class FlowState = TaintedPath::FlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    state = source.(TaintedPath::Source).getAFlowState()
    or
    mcpRequestHandlerParamSource(source) and
    state instanceof TaintedPath::FlowState::PosixPath
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    isAnyFileAccessSink(sink) and
    state = sink.(TaintedPath::Sink).getAFlowState()
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    node instanceof TaintedPath::Sanitizer and exists(state)
    or
    node = DataFlow::MakeStateBarrierGuard<FlowState, TaintedPath::BarrierGuard>::getABarrierNode(state)
  }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::MakeBarrierGuard<TaintedPath::BarrierGuard>::getABarrierNode()
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    TaintedPath::isAdditionalFlowStep(node1, state1, node2, state2)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module McpTaintedPathFlow = DataFlow::GlobalWithState<McpTaintedPathConfig>;
