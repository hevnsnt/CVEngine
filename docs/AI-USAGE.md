# AI model usage

Once an AI model is connected, the Setup menu shows **AI Model Usage**. It tracks every call CVEngine makes to Anthropic, OpenAI, OpenRouter, Ollama, or vLLM, refreshing every 15 seconds:

- calls per day and per pipeline stage, including failed ones with a safe error category;
- the model that answered, input and output tokens as the provider reports them, and latency;
- connection health: a recent successful call, a recent error, an old verification, or not yet verified. Changing the provider, model, server, or key resets it.

## Cost estimates

An App Admin enters the price for each exact provider and model ID: USD per million input and output tokens, optional cache rates, a public HTTPS source URL, and the date checked. CVEngine multiplies it by the tokens used to show a **known estimated cost**. Calls without token counts or without a matching price are counted separately as **unknown cost**, so the estimate never pretends to be complete. It is an estimate, not an invoice, and local models still cost the hardware they run on.

## Privacy

Only App Admins can see the page, call its API, or change prices. The ledger stores no API keys, prompts, responses, targets, or provider error bodies, and the settings API reports whether a key is set, never its value. History starts when the feature is installed.

See also: [DEPLOYMENT.md](DEPLOYMENT.md#ai-models), [documentation index](README.md).
