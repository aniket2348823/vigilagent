import importlib
import inspect
import logging
import os
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


AGENT_MODULES = [
    "backend.agents.alpha",
    "backend.agents.beta",
    "backend.agents.gamma",
    "backend.agents.kappa",
    "backend.agents.omega",
    "backend.agents.sigma",
    "backend.agents.zeta",
    "backend.agents.delta",
    "backend.agents.prism",
    "backend.agents.chi",
    "backend.agents.lambda_agent",
    "backend.agents.commanders.network_commander",
]


def _agent_key(class_name: str) -> str:
    return class_name.replace("Agent", "").lower()


@lru_cache(maxsize=1)
def discover_agent_classes() -> dict[str, type]:
    discovered: dict[str, type] = {}
    for module_path in AGENT_MODULES:
        try:
            module = importlib.import_module(module_path)
        except Exception as e:
            import logging

            logging.debug(f"Agent module import failed for {module_path}: {e}")
            continue
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if name.endswith("Agent") or name.startswith("Agent") or name.endswith("Commander"):
                discovered[_agent_key(name)] = obj
    return discovered


def create_agent(class_name: str, *args: Any, model_override: str | None = None, **kwargs: Any) -> Any:
    classes = discover_agent_classes()
    if class_name not in classes:
        raise KeyError(f"Unknown agent class: {class_name}")
    model = model_override or os.getenv(f"VIGILAGENT_{_agent_key(class_name)}_MODEL") or os.getenv("VIGILAGENT_MODEL")
    agent = classes[class_name](*args, **kwargs)
    if model is not None:
        agent.model_override = model
    return agent
