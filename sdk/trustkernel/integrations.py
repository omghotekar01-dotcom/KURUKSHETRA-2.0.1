from __future__ import annotations
from typing import Any, Callable, Dict, TypeVar
from .client import TrustKernelClient, GuardedExecution

T = TypeVar("T")


def guard_callable(client: TrustKernelClient, executor: Callable[[Dict[str, Any]], T], *, agent_id: str, tool: str, operation: str, resource: str = "") -> Callable[..., GuardedExecution[T]]:
    """Dependency-free adapter for tool frameworks such as LangChain, LangGraph or AutoGen."""
    def guarded(*, user_request: str, metadata: Dict[str, Any] | None = None, **kwargs: Any) -> GuardedExecution[T]:
        def invoke(effective_action: Dict[str, Any]) -> T:
            return executor({**effective_action, "tool_args": kwargs})
        return client.execute_guarded(
            invoke,
            agent_id=agent_id,
            user_request=user_request,
            tool=tool,
            operation=operation,
            resource=resource,
            metadata=metadata or {},
        )
    return guarded


class MCPGuard:
    """Supplies MCP provenance/resource metadata to the TrustKernel gateway."""

    def __init__(self, client: TrustKernelClient, *, agent_id: str, server_id: str, canonical_uri: str, manifest_sha256: str) -> None:
        self.client = client
        self.agent_id = agent_id
        self.server_id = server_id
        self.canonical_uri = canonical_uri.rstrip("/")
        self.manifest_sha256 = manifest_sha256

    def evaluate_call(self, *, user_request: str, tool_name: str, scopes: list[str] | None = None):
        return self.client.evaluate_action(
            agent_id=self.agent_id,
            user_request=user_request,
            tool="mcp_tool",
            operation="call",
            resource=tool_name,
            destination=self.canonical_uri,
            metadata={
                "source_kind": "mcp",
                "mcp_server_id": self.server_id,
                "manifest_sha256": self.manifest_sha256,
                "token_resource": self.canonical_uri,
                "requested_scopes": scopes or [],
            },
        )
