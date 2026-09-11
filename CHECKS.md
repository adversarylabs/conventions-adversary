# Checks

`review/conventions` checks changed code against evidence-backed repository
conventions rather than a universal style guide.

| Area | Evidence considered |
| --- | --- |
| Declared policy | Applicable agent instructions, contributor and style guides, formatter and linter configuration, build rules, and test configuration |
| Local implementation | Repeated patterns in the same component, package, or directory |
| Cross-implementation consistency | Sibling language, platform, adapter, and backend implementations |
| APIs and errors | Established public naming, parameter, return-value, error, logging, and compatibility patterns |
| State and architecture | Ownership, lifecycle, layering, dependency, persistence, and configuration conventions |
| Tests | Repository-specific test structure, assertion patterns, fixtures, and coverage expectations |
| Declared file placement | Exact same-directory, adjacency, named-folder, and counterpart relationships stated by an applicable repository policy |

## Evidence threshold

A declared convention needs one authoritative repository source that applies to
the changed code. An inferred convention needs at least three consistent,
independent examples in an applicable scope. Every finding must also cite the
changed line that deviates from that convention. Generic best practices,
personal taste, and single-example mimicry are outside this adversary's scope.
Common layouts such as `__tests__` are never violations by themselves; file
placement is reported only when an applicable authoritative policy states the
relationship and the concrete counterpart path proves the mismatch.
