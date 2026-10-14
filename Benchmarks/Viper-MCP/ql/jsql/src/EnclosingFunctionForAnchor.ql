/**
 * @name Enclosing function for vulnerability anchors
 * @description Emits function ranges so the post-processor can attach each
 *              SARIF alert to the smallest enclosing JavaScript/TypeScript
 *              function used as a fuzzing anchor.
 * @kind table
 * @id js/mcp-enclosing-function-for-anchor
 */

import javascript

from Function f
where
  exists(f.getFile()) and
  f.getLocation().getStartLine() > 0 and
  f.getLocation().getEndLine() >= f.getLocation().getStartLine()
select
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine(),
  f.describe()
