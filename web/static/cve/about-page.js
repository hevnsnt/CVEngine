// "About this page": the one sentence that says what a page is for. On a desktop it is cut at the end of the head's line, on a phone the head is not drawn at
// all, so a person never read it. This adds a button beside the head that opens the whole sentence under it, with a tap, Enter or Space; Escape closes it and
// gives the focus back to the button. The button shows only while the sentence is cut or hidden (it follows the window's width), so a page whose sentence
// already fits has nothing extra. The sentence is the page's own `.sub` text, so there is nothing to keep in step.
let counter = 0;

// true when the head is not drawn (a phone: it is clipped to one pixel) or its sentence is cut by the line's end
export function sentenceHidden(head, sub) {
  const box = head.getBoundingClientRect();
  if (box.width < 8 || box.height < 8) return true;
  return sub.scrollWidth > sub.clientWidth + 1 || sub.scrollHeight > sub.clientHeight + 1;
}

export function mountAbout(doc = document) {
  const head = doc.querySelector("main .page-head");
  const sub = head && head.querySelector(".sub");
  if (!head || !sub || head.parentElement.querySelector(":scope > .about-btn")) return null;
  const id = `about-page-${++counter}`;
  const button = doc.createElement("button");
  button.type = "button";
  button.className = "btn sm ghost about-btn";
  button.textContent = "About this page";
  button.setAttribute("aria-expanded", "false");
  button.setAttribute("aria-controls", id);
  button.hidden = true;
  const panel = doc.createElement("p");
  panel.className = "about-text";
  panel.id = id;
  panel.hidden = true;
  head.after(button, panel);
  const words = () => (panel.textContent = sub.textContent.replace(/\s+/g, " ").trim());
  const close = (back) => {
    panel.hidden = true;
    button.setAttribute("aria-expanded", "false");
    if (back) button.focus();
  };
  const sync = () => {
    words();
    const need = sentenceHidden(head, sub);
    button.hidden = !need;
    if (!need) close(false);
  };
  button.addEventListener("click", () => {
    const open = panel.hidden;
    panel.hidden = !open;
    button.setAttribute("aria-expanded", String(open));
  });
  const esc = (e) => {
    if (e.key === "Escape" && !panel.hidden) {
      e.preventDefault();
      close(true);
    }
  };
  button.addEventListener("keydown", esc);
  panel.addEventListener("keydown", esc);
  sync();
  if (typeof ResizeObserver === "function") new ResizeObserver(sync).observe(head);
  window.addEventListener("resize", sync);
  if (typeof MutationObserver === "function") new MutationObserver(sync).observe(sub, { childList: true, characterData: true, subtree: true });
  return { button, panel, sync };
}

if (typeof document !== "undefined") mountAbout();
