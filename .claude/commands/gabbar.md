---
description: Hand a task to Gabbar — release manager.
argument-hint: <release task, or leave empty to cut this week's release>
---

Use the Agent tool with `subagent_type: "gabbar"` and pass the task below as the prompt.

Gabbar gathers the week's unreleased work, decides the version bump, assembles
the changelog, publishes, and mirrors to the CDN. Releases are weekly, on
Friday, and only on Shakaal's go-ahead — if that go-ahead has not been given,
say so before delegating rather than releasing untested work.

Gabbar does not write product code.

Task (if empty: cut this week's release):

$ARGUMENTS
