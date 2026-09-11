from sdk.trustkernel import TrustKernelClient

kernel = TrustKernelClient()

verdict = kernel.evaluate_action(
    agent_id="finance-agent",
    user_request="Process approved vendor invoices according to company policy.",
    tool="payment",
    operation="pay",
    resource="invoice-884",
    amount=95000,
    allowed_tools=["payment"],
    constraints={"payment_auto_limit": 50000},
)

print(verdict.decision, verdict.risk_score, verdict.audit_id)
