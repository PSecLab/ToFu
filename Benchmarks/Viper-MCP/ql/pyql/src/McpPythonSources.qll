import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

private predicate hasDecoratorName(Function func, string name) {
  exists(Attribute decorator |
    func.getADecorator() = decorator and
    decorator.getName() = name
  )
  or
  exists(Call decoratorCall, Attribute decorator |
    func.getADecorator() = decoratorCall and
    decoratorCall.getFunc() = decorator and
    decorator.getName() = name
  )
}

private predicate isLikelyFastMcpModule(Module mod) {
  exists(Call call, Name callee |
    call.getFunc() = callee and
    callee.getId() = "FastMCP" and
    call.getScope().getEnclosingModule() = mod
  )
  or
  exists(Call call, Attribute callee |
    call.getFunc() = callee and
    callee.getName() = "FastMCP" and
    call.getScope().getEnclosingModule() = mod
  )
}

predicate isMcpLowLevelCallToolHandler(Function func) {
  hasDecoratorName(func, "call_tool")
}

predicate isMcpFastToolHandler(Function func) {
  hasDecoratorName(func, "tool") and
  isLikelyFastMcpModule(func.getScope().getEnclosingModule())
}

predicate isMcpContextParameter(Parameter param) {
  exists(Name name |
    param.asName() = name and
    name.getId() in ["ctx", "context"]
  )
  or
  exists(Name annotation |
    param.getAnnotation() = annotation and
    annotation.getId() = "Context"
  )
  or
  exists(Attribute annotation |
    param.getAnnotation() = annotation and
    annotation.getName() = "Context"
  )
}

class McpRemoteInput extends RemoteFlowSource::Range, DataFlow::ParameterNode {
  McpRemoteInput() {
    exists(Function func |
      isMcpLowLevelCallToolHandler(func) and
      (
        this.getParameter() in [func.getArgByName("name"), func.getArgByName("arguments")]
        or
        not exists(func.getArgByName("name")) and
        not exists(func.getArgByName("arguments")) and
        (
          not func.getArg(0).isSelf() and
          this.getParameter() in [func.getArg(0), func.getArg(1)]
          or
          func.getArg(0).isSelf() and
          this.getParameter() in [func.getArg(1), func.getArg(2)]
        )
      )
    )
    or
    exists(Function func, Parameter param |
      isMcpFastToolHandler(func) and
      param = this.getParameter() and
      (
        param = func.getAnArg()
        or
        param = func.getAKeywordOnlyArg()
        or
        param = func.getVararg()
        or
        param = func.getKwarg()
      ) and
      not param.isSelf() and
      not isMcpContextParameter(param)
    )
  }

  override string getSourceType() { result = "MCP tool input" }
}
