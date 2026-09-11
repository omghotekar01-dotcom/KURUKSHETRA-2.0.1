from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict

from .client import GuardedExecution, TrustKernelClient


@dataclass
class FrameworkGuard:
    client: TrustKernelClient
    agent_id: str
    framework: str
    tool: str
    operation: str = "invoke"
    resource: str = ""

    def protect(self, executor: Callable[[Any], Any], *, request_text: Callable[[Any], str] | None = None):
        """Return a drop-in callable that guards one framework execution boundary.

        This adapter intentionally uses duck typing and adds no LangChain,
        LangGraph or AutoGen dependency to the core SDK.
        """

        def wrapped(payload: Any):
            user_request = request_text(payload) if request_text else str(payload)

            def invoke(effective_action: Dict[str, Any]):
                return executor(payload)

            return self.client.execute_guarded(
                invoke,
                agent_id=self.agent_id,
                user_request=user_request,
                tool=self.tool,
                operation=self.operation,
                resource=self.resource,
                metadata={"framework": self.framework, "integration": "trustkernel-sdk"},
            )

        return wrapped


def protect_langchain_tool(client: TrustKernelClient, tool: Any, *, agent_id: str, tool_name: str | None = None):
    """Guard a LangChain-style Tool/BaseTool object without importing LangChain."""
    name = tool_name or getattr(tool, "name", tool.__class__.__name__)

    def executor(payload: Any):
        if hasattr(tool, "invoke"):
            return tool.invoke(payload)
        if callable(tool):
            return tool(payload)
        raise TypeError("LangChain tool adapter requires an invoke() method or callable object")

    return FrameworkGuard(client, agent_id, "langchain", name).protect(executor)


def protect_langgraph_node(client: TrustKernelClient, node: Callable[[Any], Any], *, agent_id: str, node_name: str = "langgraph-node"):
    """Guard a LangGraph node function at the node execution boundary."""
    return FrameworkGuard(client, agent_id, "langgraph", node_name, operation="node_execute").protect(node)


def protect_autogen_function(client: TrustKernelClient, function: Callable[..., Any], *, agent_id: str, function_name: str | None = None):
    """Guard an AutoGen-registered function while preserving kwargs semantics."""
    name = function_name or getattr(function, "__name__", "autogen-function")

    def wrapped(**kwargs: Any) -> GuardedExecution[Any]:
        def invoke(effective_action: Dict[str, Any]):
            return function(**kwargs)

        return client.execute_guarded(
            invoke,
            agent_id=agent_id,
            user_request=str(kwargs),
            tool=name,
            operation="function_call",
            metadata={"framework": "autogen", "integration": "trustkernel-sdk"},
        )

    return wrapped


def protect_mcp_callable(
    client: TrustKernelClient,
    executor: Callable[[Dict[str, Any]], Any],
    *,
    agent_id: str,
    server_id: str,
    canonical_uri: str,
    manifest_sha256: str,
    tool_name: str,
    requested_scopes: list[str] | None = None,
):
    """Guard an MCP tool call with registered server and token-resource metadata."""
    uri = canonical_uri.rstrip("/")

    def wrapped(arguments: Dict[str, Any], *, user_request: str = "MCP tool call") -> GuardedExecution[Any]:
        def invoke(effective_action: Dict[str, Any]):
            return executor(arguments)

        return client.execute_guarded(
            invoke,
            agent_id=agent_id,
            user_request=user_request,
            tool="mcp_tool",
            operation="call",
            resource=tool_name,
            destination=uri,
            metadata={
                "framework": "mcp",
                "source_kind": "mcp",
                "mcp_server_id": server_id,
                "manifest_sha256": manifest_sha256,
                "token_resource": uri,
                "requested_scopes": requested_scopes or [],
            },
        )

    return wrapped
