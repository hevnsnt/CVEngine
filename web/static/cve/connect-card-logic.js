// The "Connect an agent" card of the API keys page: what each command says before a key exists and after one is created.
// The key is held in the closure of one card and nowhere else (never storage, the address or a data attribute): dismiss, a reload or
// leaving the page and it is gone. These are pure functions so the state machine can be tested without a browser.
export const PLACEHOLDER = '<your token>';
export const TABS = [['tell', 'Tell your agent'], ['claude', 'Claude Code'], ['mcp', 'Other MCP clients'], ['rest', 'REST']];

export function commands({ origin, token }) {
  const t = token || PLACEHOLDER;
  const url = `${origin}/mcp/`;
  return {
    url,
    tell: `Add the cvENGINE MCP server to your tools: URL ${url}, transport Streamable HTTP, header Authorization: Bearer ${t}. Then call whoami and list_projects to confirm it works.`,
    claude: `claude mcp add --transport http cvengine ${url} --header "Authorization: Bearer ${t}"`,
    mcp: JSON.stringify({ mcpServers: { cvengine: { url, headers: { Authorization: `Bearer ${t}` } } } }, null, 2),
    rest: `curl -H "Authorization: Bearer ${t}" ${origin}/api/v1/me`,
  };
}

export function createCard(origin) {
  let token = null;
  let tab = 'tell';
  return {
    reveal(value) { token = String(value); },
    dismiss() { token = null; },
    select(name) { if (TABS.some(([k]) => k === name)) tab = name; },
    view() {
      return {
        filled: token !== null,
        token,
        tab,
        commands: commands({ origin, token }),
        hint: token === null ? 'Create a token above and this fills in.' : 'This is the only time the token is shown. Copy it now; leaving or reloading this page clears it.',
        announce: token === null ? '' : 'Token created. Commands updated.',
      };
    },
  };
}
