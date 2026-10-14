/**
 * @name JavaScript function call edges for anchor mapping
 * @description Emits resolved caller -> callee function edges so the anchor
 *              post-processor can map MCP tool roots onto helper/anchor
 *              functions through the local call graph.
 * @kind table
 * @id js/function-call-edges-for-anchor
 */

import javascript

from CallExpr call, Function caller, Function callee
where
  caller = call.getContainer().(Function) and
  callee = call.getResolvedCallee() and
  exists(caller.getLocation().getFile()) and
  exists(callee.getLocation().getFile())
select
  caller.getLocation().getFile().getRelativePath(),
  caller.getLocation().getStartLine(),
  caller.describe(),
  callee.getLocation().getFile().getRelativePath(),
  callee.getLocation().getStartLine(),
  callee.describe()
