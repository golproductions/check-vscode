const vscode = require('vscode');
const crypto = require('crypto');
const os = require('os');

const API = 'https://triage.golproductions.com/preflight';
const INSTANT = 'https://triage.golproductions.com/instant-key';
const CHANNEL = 'vscode';

let statusBarItem;

// Stable, anonymous device fingerprint. Contains no personal data: a one-way
// SHA-256 of VS Code's machine id plus coarse OS facts. The server uses it only
// to rate-limit free-key minting, never to identify a person.
function deviceFingerprint() {
  const seed = [vscode.env.machineId || '', os.platform(), os.arch(), os.hostname()].join('|');
  return crypto.createHash('sha256').update(seed).digest('hex');
}

// Mint a free key: no email, no browser, no copy-paste. Stores it in config and
// returns it. Only ever called when no key is configured, so it mints once.
async function mintInstantKey() {
  try {
    const res = await fetch(INSTANT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: deviceFingerprint(), channel: CHANNEL })
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || !data.client_id) return null;
    await vscode.workspace.getConfiguration('golCheck').update('clientId', data.client_id, vscode.ConfigurationTarget.Global);
    return data.client_id;
  } catch {
    return null;
  }
}

function activate(context) {
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = '$(shield) Check';
  statusBarItem.tooltip = 'GOL Check — Anti-Hallucination Firewall';
  statusBarItem.command = 'golCheck.showStatus';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  context.subscriptions.push(
    vscode.commands.registerCommand('golCheck.validateCommand', async () => {
      const input = await vscode.window.showInputBox({
        prompt: 'Enter a shell command to validate',
        placeHolder: 'e.g. curl https://api.example.com/v1/data'
      });
      if (input) await validateAndShow(input);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('golCheck.validateClipboard', async () => {
      const clip = await vscode.env.clipboard.readText();
      if (!clip || !clip.trim()) {
        vscode.window.showWarningMessage('Check: Clipboard is empty.');
        return;
      }
      await validateAndShow(clip.trim());
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('golCheck.showStatus', async () => {
      const config = vscode.workspace.getConfiguration('golCheck');
      const clientId = config.get('clientId');
      if (!clientId) {
        await onboard();
        return;
      }
      const enabled = config.get('enabled');
      const auto = config.get('autoValidate');
      vscode.window.showInformationMessage(
        `Check: ${enabled ? 'Active' : 'Disabled'} | Auto-validate: ${auto ? 'On' : 'Off'} | Client ID: ${clientId ? 'Set' : 'Not set'}`
      );
    })
  );

  // First run with no key: activate instantly. No email, no browser, no paste.
  const config = vscode.workspace.getConfiguration('golCheck');
  if (!config.get('clientId')) {
    onboard();
  }

  if (config.get('autoValidate') && config.get('enabled')) {
    setupShellIntegration(context);
  }
}

// Frictionless onboarding: mint a key in the background. Falls back to a manual
// key entry only if minting fails (offline, or this network hit its daily limit).
async function onboard() {
  statusBarItem.text = '$(loading~spin) Check: activating...';
  const id = await mintInstantKey();
  if (id) {
    statusBarItem.text = '$(shield) Check';
    statusBarItem.backgroundColor = undefined;
    vscode.window.showInformationMessage('GOL Check is active. 120 free checks per day. Your code is now protected.');
    return;
  }
  statusBarItem.text = '$(warning) Check: No Key';
  statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  const action = await vscode.window.showWarningMessage(
    'GOL Check could not activate automatically. Retry, or enter a key you already have.',
    'Retry',
    'I Have a Key'
  );
  if (action === 'Retry') {
    await onboard();
  } else if (action === 'I Have a Key') {
    const key = await vscode.window.showInputBox({
      prompt: 'Enter your GOL Check Client ID',
      placeHolder: 'your_client_id_here',
      ignoreFocusOut: true
    });
    if (key && key.trim()) {
      await vscode.workspace.getConfiguration('golCheck').update('clientId', key.trim(), vscode.ConfigurationTarget.Global);
      statusBarItem.text = '$(shield) Check';
      statusBarItem.backgroundColor = undefined;
      vscode.window.showInformationMessage('GOL Check is active. Your code is now protected.');
    }
  }
}

function setupShellIntegration(context) {
  if (!vscode.window.onDidExecuteTerminalCommand) return;

  context.subscriptions.push(
    vscode.window.onDidExecuteTerminalCommand(async (e) => {
      const config = vscode.workspace.getConfiguration('golCheck');
      if (!config.get('enabled') || !config.get('autoValidate')) return;
      if (!e.commandLine || !e.commandLine.trim()) return;

      const result = await validate(e.commandLine.trim());
      if (result && result.verdict === 'invalid') {
        vscode.window.showWarningMessage(`Check blocked: ${e.commandLine.substring(0, 80)}... — ${result.reason || 'invalid command'}`);
      }
    })
  );
}

async function validate(command) {
  const config = vscode.workspace.getConfiguration('golCheck');
  let clientId = config.get('clientId');

  // No key yet (e.g. first command before onboarding finished): mint silently.
  if (!clientId) {
    clientId = await mintInstantKey();
    if (!clientId) {
      vscode.window.showWarningMessage('Check could not activate. Run "GOL Check: Show Status" to retry.');
      return null;
    }
  }

  try {
    const res = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-GOL-CLIENT-ID': clientId },
      body: JSON.stringify({ command, channel: CHANNEL })
    });

    if (!res.ok) {
      let reason = `Check API error: ${res.status}`;
      try {
        const body = await res.json();
        if (res.status === 402) reason = body.upgrade || 'Daily free checks used up. Top up at golproductions.com/console.html';
        else if (body.error || body.reason) reason = body.reason || body.error;
      } catch {}
      vscode.window.showWarningMessage(reason);
      return null;
    }

    return await res.json();
  } catch (err) {
    vscode.window.showErrorMessage(`Check: Network error — ${err.message}`);
    return null;
  }
}

async function validateAndShow(command) {
  statusBarItem.text = '$(loading~spin) Check...';
  const result = await validate(command);
  statusBarItem.text = '$(shield) Check';

  if (!result) return;

  if (result.verdict === 'runnable') {
    vscode.window.showInformationMessage(`Check: ✓ Runnable — ${command.substring(0, 80)}`);
  } else {
    vscode.window.showWarningMessage(`Check: ✗ Invalid — ${result.reason || command.substring(0, 80)}`);
  }
}

function deactivate() {
  if (statusBarItem) statusBarItem.dispose();
}

module.exports = { activate, deactivate };
