// Old Administration deep links that moved. `#agents` was the Agents tab; Sentinels now have a page of their own.
export function legacyAdminTarget(hash) {
  return hash === '#agents' ? '/cve/sentinels/' : null;
}
