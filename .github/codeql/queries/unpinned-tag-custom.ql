/**
 * @name Unpinned tag for a non-immutable Action
 * @description Flags workflow steps using mutable version tags instead of
 *              pinned commit SHAs, excluding trusted internal victory-live actions.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id actions/unpinned-tag
 * @tags actions security external/cwe/cwe-829
 */

import actions

from UsesStep step
where
  // Has a ref that looks like a version tag (v1, v1.2, etc.) not a SHA
  step.getRef().regexpMatch("v\\d+.*")
  // Is not pinned to a full commit SHA (40 hex chars)
  and not step.getRef().regexpMatch("[0-9a-f]{40}")
  // Exclude internal victory-live org actions
  and not step.getCallee().matches("victory-live/%")
select step,
  "Unpinned tag '" + step.getRef() + "' used in step '" + step.getId() + "'. Pin to a full commit SHA instead."
