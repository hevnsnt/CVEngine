// The MCP page (cveFeed/templates/cveFeed/mcp.html): a Copy button beside the server address and each setup copies the text of the element it
// names (data-copy-from), and says so on the button for a moment. The page works without it: the text can be selected by hand.
import { copyText } from "/staticfiles/cve/ui.js";

for (const button of document.querySelectorAll("[data-copy-from]")) {
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copyFrom);
    if (!source) return;
    const label = button.textContent;
    try {
      await copyText(source.textContent.trim());
      button.textContent = "Copied";
    } catch {
      button.textContent = "Select and copy";
    }
    setTimeout(() => { button.textContent = label; }, 1600);
  });
}
