// The Overview's note "your first look is still under way": hidden unless the first-run wizard sent the user here (?first=1) and the first
// counts say there is no host yet. It goes away on the next poll after the first host appears.
export function firstNoteHidden(first, stats) {
  return !(first && stats && !stats.hosts);
}
