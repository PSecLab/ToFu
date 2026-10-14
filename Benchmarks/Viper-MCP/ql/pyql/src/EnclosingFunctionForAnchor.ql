/**
 * @name Enclosing function for Python vulnerability anchors
 * @description Emits Python function ranges so the post-processor can attach
 *              each SARIF alert to the smallest enclosing function used as a
 *              fuzzing anchor.
 * @kind table
 * @id py/mcp-enclosing-function-for-anchor
 */

import python

from Function f
where
  f.getLocation().getStartLine() > 0 and
  exists(f.getLastStatement()) and
  f.getLastStatement().getLocation().getEndLine() >= f.getLocation().getStartLine()
select
  f.getLocation().getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLastStatement().getLocation().getEndLine(),
  f.getQualifiedName()
