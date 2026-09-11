import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.PathInjectionCustomizations
import McpPythonSources

abstract private class NormalizationState extends string {
  bindingset[this]
  NormalizationState() { any() }
}

class NotNormalized extends NormalizationState {
  NotNormalized() { this = "NotNormalized" }
}

class NormalizedUnchecked extends NormalizationState {
  NormalizedUnchecked() { this = "NormalizedUnchecked" }
}

module McpPyPathInjectionConfig implements DataFlow::StateConfigSig {
  class FlowState = NormalizationState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof PathInjection::Source and state instanceof NotNormalized
    or
    source instanceof McpRemoteInput and state instanceof NotNormalized
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof PathInjection::Sink and
    (
      state instanceof NotNormalized
      or
      state instanceof NormalizedUnchecked
    )
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof PathInjection::Sanitizer }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    node instanceof Path::PathNormalization and
    state instanceof NotNormalized
    or
    node instanceof Path::SafeAccessCheck and
    state instanceof NormalizedUnchecked
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
  ) {
    nodeFrom = nodeTo.(Path::PathNormalization).getPathArg() and
    stateFrom instanceof NotNormalized and
    stateTo instanceof NormalizedUnchecked
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module McpPyPathInjectionFlow = TaintTracking::GlobalWithState<McpPyPathInjectionConfig>;
