// The copy-paste commands for the host inventory reporter scripts, as pure functions (no DOM), so what a person is told to run is tested.
// The scripts are served by this server at SCRIPT_PATH. The token is a placeholder until one has just been created in the dialog.
export const SCRIPT_PATH = "/staticfiles/cve/inventory/";
const SAFE = /^[A-Za-z0-9._:/@[\]-]+$/;

// Everything that goes into a command is checked, so a project slug or address can never add a second command.
const plain = (value, what) => {
  if (typeof value !== "string" || !SAFE.test(value)) throw new Error(`${what} has characters that do not belong in a command`);
  return value;
};

// The token is never in a command: a command is saved in shell history and shown in the process list. The Linux and macOS command
// reads it from the keyboard into a file only its owner can read (paste it, Enter, Ctrl-D); the Windows one reads it as a secure
// string into the environment of this session. Both are asked for before anything is downloaded.
export function snippets({ origin, project, privateCa = true }) {
  const server = plain(origin, "the server address");
  const slug = plain(project, "the project");
  const script = (file) => `${server}${SCRIPT_PATH}${file}`;
  const curlCa = privateCa ? " --cacert ca.crt" : "";
  const scriptCa = privateCa ? " --ca-file ca.crt" : "";
  const target = `--server ${server} --project ${slug} --token-file cvengine-inventory.token${scriptCa}`;
  const readToken = "(umask 077; cat > cvengine-inventory.token)";
  return {
    linux: `${readToken} && curl -fsS${curlCa} ${script("cvengine-inventory.sh")} -o cvengine-inventory.sh && sh cvengine-inventory.sh ${target}`,
    python: `${readToken} && curl -fsS${curlCa} ${script("cvengine-inventory.py")} -o cvengine-inventory.py && python3 cvengine-inventory.py ${target}`,
    windows:
      "$env:CVENGINE_TOKEN = [System.Net.NetworkCredential]::new('', (Read-Host 'Token' -AsSecureString)).Password; " +
      // Invoke-WebRequest would not trust a private CA; curl.exe (in Windows 10 1803 and later) takes the installer's certificate
      (privateCa
        ? `curl.exe -fsS --cacert ca.crt ${script("cvengine-inventory.ps1")} -o cvengine-inventory.ps1; `
        : `Invoke-WebRequest ${script("cvengine-inventory.ps1")} -OutFile cvengine-inventory.ps1; `) +
      `powershell -NoProfile -ExecutionPolicy Bypass -File .\\cvengine-inventory.ps1 -Server ${server} -Project ${slug}${privateCa ? " -CaFile .\\ca.crt" : ""}`,
    check: `sh cvengine-inventory.sh --dry-run`,
    checkWindows: `powershell -NoProfile -ExecutionPolicy Bypass -File .\\cvengine-inventory.ps1 -DryRun`,
    schedule: `sh cvengine-inventory.sh --install-cron --server ${server} --project ${slug}`,
    scheduleWindows: `powershell -NoProfile -ExecutionPolicy Bypass -File .\\cvengine-inventory.ps1 -Schedule -Server ${server} -Project ${slug}`,
  };
}

// "3 hours", "2 days": how old a report is, for people
export function ageWord(hours) {
  if (hours == null || Number.isNaN(Number(hours))) return "unknown age";
  const h = Number(hours);
  if (h < 1) return "under an hour";
  if (h < 48) return `${Math.round(h)} hour${Math.round(h) === 1 ? "" : "s"}`;
  const d = Math.floor(h / 24);
  return d < 90 ? `${d} days` : `${Math.floor(d / 30)} months`;
}
