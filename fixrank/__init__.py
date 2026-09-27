"""fixrank: rank security findings by what to fix first, with an auditable rationale per finding."""

__version__ = "0.1.0"


class FixrankError(Exception):
    """A usage or configuration problem. The CLI reports it and exits 2."""
