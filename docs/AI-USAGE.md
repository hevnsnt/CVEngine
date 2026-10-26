# AI model usage

Once an AI model is connected, the account menu shows **AI Model Usage** (superusers), refreshed every 15 seconds. It records every completion cvENGINE requests from Anthropic, OpenAI, OpenRouter, Ollama, vLLM, or LM Studio:

- calls per day and per pipeline stage, including failed ones with a safe error category (choose 24 hours, 7 days, or 30 days);
- the model that answered, input, output, and cache tokens as the provider reports them, and latency;
- connection health: a recent successful call, a recent error, an old verification, or not yet verified. Changing the provider, model, server, or key resets it.

## Cost estimates

An App Admin enters the price for each exact provider and model ID: USD per million input and output tokens, cache rates, an HTTPS source URL, and the date checked. cvENGINE multiplies it by the tokens used to show a **known estimated cost**. Calls without token counts, without a matching price, or with cached tokens but no cache rate count separately as **unknown cost**, so the estimate never pretends to be complete. It is an estimate, not an invoice, and local models still cost the hardware they run on.

## Privacy

Only App Admins can see the page, call its API (`GET /cve/api/settings/ai/usage`), or change prices. The ledger stores no API keys, prompts, responses, targets, or provider error bodies, and the settings API reports whether a key is set, never its value. History starts when the feature is installed, and rows are removed after 400 days (`CVENGINE_AI_USAGE_RETENTION_DAYS`).

See also: [DEPLOYMENT.md](DEPLOYMENT.md#ai-models), [documentation index](README.md).
