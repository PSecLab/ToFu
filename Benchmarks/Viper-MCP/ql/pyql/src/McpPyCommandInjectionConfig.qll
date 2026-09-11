import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CommandInjectionCustomizations
import McpPythonSources

module McpPyCommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CommandInjection::Source
    or
    source instanceof McpRemoteInput
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CommandInjection::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module McpPyCommandInjectionFlow = TaintTracking::Global<McpPyCommandInjectionConfig>;
