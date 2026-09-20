package handler

import "fmt"

// mcpInstallHTML only receives a plaintext token in the one-time creation response.
// Existing tokens must be supplied by the user; stored hashes cannot recover them.
func mcpInstallHTML(raw string) string {
	return fmt.Sprintf(`
    <section class="%s" aria-labelledby="mcp-install-title">
      <h2 id="mcp-install-title" class="%s">Install SIR OCR MCP</h2>
      <p class="text-sm %s mb-4">Connect Claude Code or Codex CLI to SIR OCR. Copy a command and run it in Bash / Zsh on macOS, Linux or WSL with the chosen CLI already installed.</p>
      <label for="mcp-token" class="%s">Personal access token</label>
      <input id="mcp-token" type="password" value="%s" placeholder="sirpat_…" autocomplete="off" spellcheck="false" class="%s font-mono mt-2" aria-describedby="mcp-token-note">
      <p id="mcp-token-note" class="text-xs %s mt-2 mb-4">A newly created token is filled in automatically. For an existing token, paste the full value you saved; it cannot be retrieved. This field is used only in this page and is not saved.</p>
      <div class="flex flex-wrap gap-3">
        <button id="mcp-copy-claude" type="button" class="%s" disabled>Copy Claude install</button>
        <button id="mcp-copy-codex" type="button" class="%s" disabled>Copy Codex install</button>
      </div>
      <p id="mcp-install-status" role="status" aria-live="polite" class="text-sm %s mt-3"></p>
      <details class="mt-4"><summary class="cursor-pointer text-sm font-semibold">Preview installation commands</summary>
        <p class="text-sm font-semibold mt-4 mb-2">Claude Code</p>
        <textarea id="mcp-command-claude" readonly rows="3" aria-label="Claude Code installation command" class="w-full p-3 rounded-[12px] bg-[#0a0b0d] text-white font-mono text-xs"></textarea>
        <p class="text-xs %s mt-2">Open Claude Code again after installation.</p>
        <p class="text-sm font-semibold mt-4 mb-2">Codex CLI</p>
        <textarea id="mcp-command-codex" readonly rows="4" aria-label="Codex CLI installation command" class="w-full p-3 rounded-[12px] bg-[#0a0b0d] text-white font-mono text-xs"></textarea>
        <p class="text-xs %s mt-2">Run in the same terminal. In a new terminal, set SIR_PAT again before starting Codex.</p>
      </details>
      <p class="text-sm %s mt-4">Then ask: <code>Use sir-ocr to read /path/to/paper.pdf and summarize it.</code></p>
      <noscript><p>Enable JavaScript to generate and copy installation commands.</p></noscript>
    </section>
    <script>
    (() => {
      const token = document.getElementById('mcp-token');
      const status = document.getElementById('mcp-install-status');
      const buttons = {claude: document.getElementById('mcp-copy-claude'), codex: document.getElementById('mcp-copy-codex')};
      const fields = {claude: document.getElementById('mcp-command-claude'), codex: document.getElementById('mcp-command-codex')};
      function update() {
        const raw = token.value.trim();
        const valid = /^sirpat_[A-Za-z0-9_-]{43}$/.test(raw);
        Object.values(buttons).forEach(button => button.disabled = !valid);
        fields.claude.value = valid ? 'export SIR_PAT=\x27' + raw + '\x27\nclaude mcp add --transport http --scope user sir-ocr https://mcp.sir-labs.com/mcp --header "Authorization: Bearer $SIR_PAT"' : '';
        fields.codex.value = valid ? 'export SIR_PAT=\x27' + raw + '\x27\ncodex mcp add sir-ocr --url https://mcp.sir-labs.com/mcp --bearer-token-env-var SIR_PAT\ncodex' : '';
        status.textContent = valid ? 'Ready to copy. The command includes your token.' : raw ? 'Enter a complete SIR personal access token.' : 'Create a token above, or paste an existing token to enable installation.';
        return valid;
      }
      token.addEventListener('input', update);
      Object.entries(buttons).forEach(([client, button]) => button.addEventListener('click', async () => {
        if (!update()) return;
        try {
          await navigator.clipboard.writeText(fields[client].value);
          status.textContent = 'Copied ' + (client === 'claude' ? 'Claude Code' : 'Codex CLI') + ' installation command. Paste it into your terminal.';
        } catch {
          fields[client].closest('details').open = true;
          fields[client].focus();
          fields[client].select();
          status.textContent = 'Automatic copy is unavailable. The command is selected; press Ctrl+C or Command+C.';
        }
      }));
      update();
    })();
    </script>`, cardClass, h2Class, mutedClass, labelClass, htmlEscape(raw), inputClass, mutedClass, btnPrimary, btnPrimary, mutedClass, mutedClass, mutedClass, mutedClass)
}
