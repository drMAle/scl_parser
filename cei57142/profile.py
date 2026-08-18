"""Top-level CEI 57-142 validator."""
from .observability import validate_observability
from .semantic import validate_semantics
from .communication import validate_communication

def validate_cei57142(model, include_communication=True, include_semantics=True):
    findings=validate_observability(model)
    if include_semantics: findings.extend(validate_semantics(model))
    if include_communication: findings.extend(validate_communication(model))
    return findings
