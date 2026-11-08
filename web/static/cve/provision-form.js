// The Provision a Sentinel form's one rule: nothing is chosen for the person, so Provision stays off until every required field has a
// real choice. Returns the plain sentence that says what is missing, or '' when the form is complete. Kept free of the DOM so a node
// test (tests/test_provision_form.mjs) can hold it to that rule.
export function missingChoice(v) {
  if (!v.scope) return 'Choose a scope to continue.';
  if (v.scope === 'project' && !v.project) return 'Choose a project.';
  if (v.scope === 'org' && !v.org) return 'Choose an organization.';
  if (v.scope !== 'project' && v.scope !== 'org' && v.scope !== 'instance') return 'Choose a scope to continue.';
  if (!v.network) return 'Choose where it runs.';
  if (!v.profile) return 'Choose a size.';
  return '';
}
