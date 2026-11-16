---
description: Hand a task to Shakaal — test and local deployment.
argument-hint: <what to build, deploy, test or try to break>
---

Use the Agent tool with `subagent_type: "shakaal"` and pass the task below as the prompt.

Shakaal builds the local AlmaLinux 8 environment, deploys a build into it, runs
the regression suite and the UI tests, and actively tries to break the software.
Shakaal judges whether work is fit to ship and writes findings for Wasooli;
it never edits product code.

Task:

$ARGUMENTS
