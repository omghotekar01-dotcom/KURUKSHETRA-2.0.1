from __future__ import annotations
from typing import List, Optional
from ..models import AgentIdentity
from .storage import store


class AgentRegistry:
    def __init__(self) -> None:
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        defaults = [
            AgentIdentity(id="support-agent", name="Customer Support Agent", owner="Customer Operations", allowed_tools=["email", "file", "crm"], allowed_operations={"email": ["read", "draft", "send"], "file": ["read"], "crm": ["read", "update_ticket"]}, allowed_domains=["company.local", "customers.example"], tags=["customer-data", "external-content"]),
            AgentIdentity(id="finance-agent", name="Finance Reconciliation Agent", owner="Finance Engineering", allowed_tools=["invoice", "vendor", "payment"], allowed_operations={"invoice": ["read", "validate"], "vendor": ["lookup"], "payment": ["prepare", "pay"]}, max_payment=50000, allowed_domains=["bank.internal", "company.local"], tags=["financial"]),
            AgentIdentity(id="analytics-agent", name="Analytics Agent", owner="Data Platform", allowed_tools=["database"], allowed_operations={"database": ["select", "explain"]}, tags=["read-only"]),
            AgentIdentity(id="coordinator-agent", name="Multi-Agent Coordinator", owner="Agent Platform", allowed_tools=["memory", "agent_message", "workflow"], allowed_operations={"memory": ["read", "write"], "agent_message": ["send"], "workflow": ["trigger"]}, allowed_domains=["company.local"], tags=["multi-agent", "orchestration"]),
            AgentIdentity(id="coding-agent", name="Coding Agent", owner="Engineering", allowed_tools=["github", "shell", "file"], allowed_operations={"github": ["read", "branch", "commit", "push"], "shell": ["test", "lint", "build"], "file": ["read", "write"]}, allowed_domains=["github.com", "company.local"], tags=["developer"]),
            AgentIdentity(id="integration-agent", name="Integration/MCP Agent", owner="Agent Platform", allowed_tools=["mcp_tool", "agent_message"], allowed_operations={"mcp_tool": ["call"], "agent_message": ["send"]}, allowed_domains=["company.local"], tags=["mcp", "integrations"]),
        ]
        existing = {item["id"] for item in store.agents()}
        for agent in defaults:
            if agent.id not in existing:
                store.upsert_agent(agent.id, agent.model_dump())

    def get(self, agent_id: str, workspace_id: Optional[str] = None) -> Optional[AgentIdentity]:
        data = store.get_agent(agent_id)
        if not data:
            return None
        agent = AgentIdentity.model_validate(data)
        if workspace_id and agent.workspace_id not in {None, workspace_id}:
            return None
        return agent

    def upsert(self, agent: AgentIdentity) -> AgentIdentity:
        store.upsert_agent(agent.id, agent.model_dump())
        return agent

    def list(self, workspace_id: Optional[str] = None) -> List[AgentIdentity]:
        items = [AgentIdentity.model_validate(item) for item in store.agents()]
        if not workspace_id:
            return items
        return [item for item in items if item.workspace_id in {None, workspace_id}]


agents = AgentRegistry()
