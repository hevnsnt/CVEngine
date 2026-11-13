// What a page does when the server it talks to runs another build than the one that rendered it (an update went in while the page stayed open).
// Kept free of the DOM and of imports so that `node --test` can run it; static/cve/sitewatch.js feeds it and acts on the answer.

// "none": the same build, or one of the two is not known (a server without a stamped commit, a page from before pages carried one).
// "wait": the page is in the background; it is asked again when it comes back to the front.
// "bar": do not reload: something typed here would be lost, a dialog is open, or this tab already reloaded once for this very build (a loop guard).
// "reload": hard reload now.
export function buildAction({ page, server, hidden, dirty, dialog, reloadedFor }) {
  if (!page || !server || page === server) return "none";
  if (hidden) return "wait";
  if (dirty || dialog || reloadedFor === server) return "bar";
  return "reload";
}
