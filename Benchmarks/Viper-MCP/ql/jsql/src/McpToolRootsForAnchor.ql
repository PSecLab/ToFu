/**
 * @name MCP JavaScript tool roots for anchor mapping
 * @description Extracts MCP tool-name to handler/callback roots for JavaScript
 *              servers. Used by the anchor post-processor to recover stable
 *              top-level tool identities and map them to anchor functions.
 * @kind table
 * @id js/mcp-tool-roots-for-anchor
 */

import javascript

private predicate isCallToolHandler(Function handler) {
  exists(CallExpr call |
    call.getCalleeName() = "setRequestHandler" and
    call.getArgument(1).flow().getAFunctionValue().getFunction() = handler
  )
}

private predicate isRequestNameSwitch(SwitchStmt sw) {
  exists(PropAccess nameAccess, PropAccess paramsAccess |
    sw.getExpr() = nameAccess and
    nameAccess.getPropertyName() = "name" and
    nameAccess.getBase() = paramsAccess and
    paramsAccess.getPropertyName() = "params"
  )
}

private predicate selectToolCaseHandler(
  string toolName, Function handlerRoot, string sourceKind
) {
  exists(Function handler, SwitchStmt sw, Case c, CallExpr call |
    isCallToolHandler(handler) and
    sw.getContainer() = handler and
    isRequestNameSwitch(sw) and
    c.getSwitch() = sw and
    not c.isDefault() and
    toolName = c.getExpr().getStringValue() and
    call.getParent*() = c and
    call.getCallee() instanceof PropAccess and
    call.getCallee().(PropAccess).getBase() instanceof ThisExpr and
    handlerRoot = call.getResolvedCallee() and
    sourceKind = "switch_case_handler"
  )
}

private predicate selectAddToolExecute(
  string toolName, Function handlerRoot, string sourceKind
) {
  exists(CallExpr call, ObjectExpr obj, Property nameProp, Property execProp |
    call.getCalleeName() = "addTool" and
    obj = call.getArgument(0) and
    nameProp = obj.getPropertyByName("name") and
    execProp = obj.getPropertyByName("execute") and
    toolName = nameProp.getInit().getStringValue() and
    handlerRoot = execProp.getInit().flow().getAFunctionValue().getFunction() and
    sourceKind = "addTool_execute"
  )
}

private predicate selectServerToolCallback(
  string toolName, Function handlerRoot, string sourceKind
) {
  exists(CallExpr call, int i |
    call.getCalleeName() = "tool" and
    toolName = call.getArgument(0).getStringValue() and
    i > 0 and
    handlerRoot = call.getArgument(i).flow().getAFunctionValue().getFunction() and
    sourceKind = "server_tool_callback"
  )
}

from string toolName, Function handlerRoot, string sourceKind
where
  selectToolCaseHandler(toolName, handlerRoot, sourceKind)
  or
  selectAddToolExecute(toolName, handlerRoot, sourceKind)
  or
  selectServerToolCallback(toolName, handlerRoot, sourceKind)
select
  toolName,
  handlerRoot.getLocation().getFile().getRelativePath(),
  handlerRoot.getLocation().getStartLine(),
  handlerRoot.describe(),
  sourceKind
