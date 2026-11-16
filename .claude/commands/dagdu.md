---
description: Hand a task to Dagdu — business analyst and product owner.
argument-hint: <what you want built, changed or investigated>
---

Use the Agent tool with `subagent_type: "dagdu"` and pass the task below as the prompt.

Dagdu turns a request into a written requirement: interviews the user where the
ask is ambiguous, resolves it, writes a spec to `docs/specs/`, and hands it to
Wasooli. Dagdu does not write product code — if the task is already specified
and just needs building, say so and offer `/wasooli` instead of delegating.

Task:

$ARGUMENTS
