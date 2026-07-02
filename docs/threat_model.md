# Threat Model

Initial prototype assumptions:

- Parties are honest-but-curious.
- Parties do not collude.
- The query gateway is trusted or client-side.
- Party-local indexes remain private.
- Final top-k evidence is allowed to be revealed.

Out of scope for the first prototype:

- Private LLM inference.
- Malicious-party security.
- Full access-pattern hiding.
- Protection after `K_setup` compromise.

