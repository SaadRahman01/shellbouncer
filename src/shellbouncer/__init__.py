"""shellbouncer: a firewall for AI coding agents."""

__version__ = "0.1.0"

from .engine import Action, Verdict, evaluate, evaluate_all  # noqa: E402
from .policy import Policy, build_policy, load_policy  # noqa: E402

__all__ = ["Action", "Policy", "Verdict", "build_policy", "evaluate", "evaluate_all", "load_policy", "__version__"]
