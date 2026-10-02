# Plugin API (current, limited)

## Implemented interface

`vulnforge.plugins.base.DetectorPlugin` currently exposes metadata attributes and one synchronous method:

```python
class DetectorPlugin:
    id: str
    name: str
    category: str
    severity: str
    passive: bool
    check_class: str
    def run(self, ctx) -> list[Finding]: ...
```

Built-ins are registered through `@register` and loaded from `vulnforge.plugins`. Passive plugins analyze already collected context and should not send requests. No external-tool invocation is currently integrated.

## Important limitation

The current plugin base does not yet implement the full `discover/analyze/hypothesize/plan/execute/verify/report` lifecycle. Active plugin gating is not a general adapter safety contract. Do not add active plugins until they use the central `Requester`, declared scope/risk/cost/prerequisites, and independent evidence validation. Plugin import failures are currently skipped by the loader; observability/error accounting should be improved before a large plugin ecosystem is added.
