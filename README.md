# Repository Conventions adversary

`adversarylabs/review/conventions` reviews changed code against the conventions
of the repository being changed.

It considers both declared rules—such as contributor guides, `AGENTS.md`,
formatter and linter configuration—and conventions encoded in existing code.
An inferred convention requires several consistent examples and is rejected
when meaningful counterexamples exist. A second model pass independently
verifies every proposed finding.

The package is language-agnostic. It reports only deviations introduced by the
change and cites both the changed line and the repository evidence establishing
the convention.
