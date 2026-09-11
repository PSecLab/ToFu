import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
import McpPythonSources

module McpPyServerSideRequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ServerSideRequestForgery::Source
    or
    source instanceof McpRemoteInput
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof ServerSideRequestForgery::Sink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof ServerSideRequestForgery::Sanitizer
    or
    node instanceof ServerSideRequestForgery::FullUrlControlSanitizer
  }

  predicate observeDiffInformedIncrementalMode() { none() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.(ServerSideRequestForgery::Sink).getRequest().getLocation()
  }
}

module McpPyServerSideRequestForgeryFlow =
  TaintTracking::Global<McpPyServerSideRequestForgeryConfig>;

predicate fullyControlledRequest(Http::Client::Request request) {
  forall(DataFlow::Node urlPart | urlPart = request.getAUrlPart() |
    McpPyServerSideRequestForgeryFlow::flow(_, urlPart)
  )
}
