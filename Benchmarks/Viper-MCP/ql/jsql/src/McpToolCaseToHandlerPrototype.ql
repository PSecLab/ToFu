/**
 * @name MCP tool case to resolved handler function (prototype)
 * @description Extracts low-level MCP tools/call switch-case mappings of the
 *              form `case "tool_name": return this.someMethod(...)`.
 *              This is a prototype query for validating whether tool names can
 *              be recovered as a more stable source-side identity for anchor
 *              functions in JavaScript MCP servers.
 * @kind table
 * @id js/mcp-tool-case-to-handler-prototype
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

from Function handler, SwitchStmt sw, Case c, CallExpr call, Function callee, string toolName
where
  isCallToolHandler(handler) and
  sw.getContainer() = handler and
  isRequestNameSwitch(sw) and
  c.getSwitch() = sw and
  not c.isDefault() and
  toolName = c.getExpr().getStringValue() and
  call.getParent*() = c and
  call.getCallee() instanceof PropAccess and
  call.getCallee().(PropAccess).getBase() instanceof ThisExpr and
  callee = call.getResolvedCallee()
select
  toolName,
  callee.describe(),
  callee.getLocation().getFile().getRelativePath(),
  callee.getLocation().getStartLine()
