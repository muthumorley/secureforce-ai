import express from 'express';
import { Mppx, tempo, discovery } from 'mppx/express';
import { Store } from 'mppx/server';
import { randomUUID } from 'node:crypto';
import { scanApex, RULE_COUNT } from './scan.js';

// ---------------------------------------------------------------------------
// Config (fail fast: a payment server with a missing secret is a bug)
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 4200;
const PRICE_USD = '0.08';
const MAX_CODE_CHARS = 100_000;

const SECRET = process.env.MPP_SECRET_KEY;
const RECIPIENT = process.env.TEMPO_RECIPIENT;
if (!SECRET) throw new Error('MPP_SECRET_KEY is required. Generate one: openssl rand -hex 32');
if (!RECIPIENT || !/^0x[0-9a-fA-F]{40}$/.test(RECIPIENT)) {
  throw new Error('TEMPO_RECIPIENT must be your wallet address (0x + 40 hex chars)');
}

// ---------------------------------------------------------------------------
// MPP: this is the whole payment setup.
//  - testnet: true  -> Tempo testnet only, faucet funds, no real money
//  - currency omitted -> mppx defaults to pathUSD on testnet
//  - recipient      -> where the $0.08 payments are sent
//  - store          -> replay protection (a tx hash can pay for only ONE scan)
// ---------------------------------------------------------------------------
const mppx = Mppx.create({
  methods: [
    tempo.charge({
      recipient: RECIPIENT as `0x${string}`,
      testnet: true,
      store: Store.memory(), // single process only. Use Store.postgres() when you scale out.
    }),
  ],
  secretKey: SECRET, // signs challenges so they cannot be forged
});

// Middleware: replies 402 + challenge if unpaid, verifies the credential if paid,
// and attaches the Payment-Receipt header to the success response.
const pay = mppx.charge({ amount: PRICE_USD });

// Simple in-memory payment log (metadata only; never the submitted code).
const payments: { at: string; receiptRef: string; payer: string | null; amountUsd: string }[] = [];

const app = express();
app.use(express.json({ limit: '200kb' }));

// ---- free routes -----------------------------------------------------------
app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#0b1017">
    <meta name="description" content="Explore SecureForce AI's Apex security scan demo and Tempo testnet payment flow.">
    <title>SecureForce AI — Apex security workbench</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0b1017; color: #ecf2f5; font-synthesis: none; }
      * { box-sizing: border-box; }
      body { margin: 0; min-width: 320px; min-height: 100vh; background: radial-gradient(ellipse at 72% -12%, #16433b 0, transparent 34%), #0b1017; }
      a { color: inherit; text-decoration: none; }
      button, select, textarea { font: inherit; }
      .shell { width: min(1180px, calc(100% - 48px)); margin: 0 auto; }
      .topbar { height: 74px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #202b34; }
      .brand { display: flex; align-items: center; gap: 11px; font-size: 15px; font-weight: 750; letter-spacing: -.02em; }
      .brand-mark { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 10px; color: #07120f; background: #65e0b2; font-size: 18px; font-weight: 900; }
      .top-links { display: flex; align-items: center; gap: 25px; color: #9cabb4; font-size: 13px; }
      .top-links a:hover, .footer-links a:hover { color: #72e6bb; }
      .network-pill, .status-pill { display: inline-flex; align-items: center; gap: 8px; border: 1px solid #245047; border-radius: 999px; padding: 8px 11px; color: #91e8c9; background: #10251f; font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
      .dot { width: 7px; height: 7px; border-radius: 50%; background: #61dfa9; box-shadow: 0 0 12px #61dfa9; }
      main { padding: 58px 0 58px; }
      .hero { display: flex; justify-content: space-between; align-items: end; gap: 28px; margin-bottom: 32px; }
      .eyebrow { margin-bottom: 15px; color: #72e6bb; font-size: 11px; font-weight: 750; letter-spacing: .16em; text-transform: uppercase; }
      h1 { max-width: 680px; margin: 0; font-size: clamp(38px, 6vw, 64px); line-height: 1.04; letter-spacing: -.055em; }
      h1 span { color: #70e5b9; }
      .intro { max-width: 640px; margin: 17px 0 0; color: #9cabb4; font-size: 15px; line-height: 1.7; }
      .hero-badge { flex: 0 0 auto; margin-bottom: 5px; }
      .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 13px; margin-bottom: 22px; }
      .metric { padding: 17px 19px; border: 1px solid #202b34; border-radius: 12px; background: linear-gradient(130deg, #121b23, #10171e); }
      .metric-label { color: #81919b; font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
      .metric-value { margin-top: 8px; font-size: 20px; font-weight: 720; letter-spacing: -.025em; }
      .metric-value small { color: #91a1ab; font-size: 12px; font-weight: 500; letter-spacing: 0; }
      .workbench { display: grid; grid-template-columns: minmax(0, 1.12fr) minmax(320px, .88fr); gap: 16px; align-items: stretch; }
      .panel { overflow: hidden; border: 1px solid #26343e; border-radius: 14px; background: #111922; box-shadow: 0 22px 65px #0002; }
      .panel-head { min-height: 62px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 18px; border-bottom: 1px solid #26313a; }
      .panel-title { display: flex; align-items: center; gap: 10px; font-size: 13px; font-weight: 720; }
      .step { width: 23px; height: 23px; display: grid; place-items: center; border: 1px solid #31534c; border-radius: 7px; color: #71e3b8; font-size: 11px; }
      .editor-meta { display: flex; align-items: center; gap: 9px; color: #83929c; font-size: 11px; }
      select { max-width: 170px; padding: 8px 28px 8px 10px; border: 1px solid #2b3943; border-radius: 8px; outline: none; color: #d6e0e4; background: #151f28; font-size: 11px; }
      .editor { min-height: 328px; padding: 17px 17px 12px; background: linear-gradient(90deg, #0d141b 0, #0d141b 46px, #111922 46px); }
      textarea { display: block; width: 100%; min-height: 296px; resize: vertical; border: 0; outline: 0; color: #b9d8d1; background: transparent; font: 12px/1.8 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; tab-size: 2; white-space: pre; }
      textarea::selection { color: #f2fbf8; background: #286452; }
      .editor-foot { display: flex; justify-content: space-between; gap: 10px; padding: 10px 17px; border-top: 1px solid #26313a; color: #82919a; font-size: 10px; }
      .actions { display: flex; flex-wrap: wrap; gap: 9px; padding: 13px 17px 17px; }
      .btn { min-height: 39px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 0 14px; border: 1px solid transparent; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 720; transition: transform .15s, background .15s, border-color .15s; }
      .btn:hover { transform: translateY(-1px); }
      .btn:focus-visible, select:focus-visible, textarea:focus-visible, a:focus-visible { outline: 2px solid #70e5b9; outline-offset: 3px; }
      .btn-primary { color: #07140f; background: #69e2b5; }
      .btn-primary:hover { background: #8aefca; }
      .btn-secondary { border-color: #35444d; color: #d6e0e4; background: #17212a; }
      .btn-secondary:hover { border-color: #4a7568; background: #1a2a2e; }
      .results-body { min-height: 328px; padding: 18px; }
      .result-intro { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 18px; }
      .result-intro h2 { margin: 0; font-size: 14px; }
      .result-intro p { margin: 5px 0 0; color: #8797a0; font-size: 11px; line-height: 1.5; }
      .status-pill { padding: 6px 9px; font-size: 9px; white-space: nowrap; }
      .status-pill.neutral { border-color: #34414a; color: #a0afb7; background: #18212a; }
      .status-pill.warning { border-color: #594a2b; color: #f2ca78; background: #2b2417; }
      .status-pill.success { border-color: #245047; color: #91e8c9; background: #10251f; }
      .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 13px; }
      .stat { padding: 11px; border: 1px solid #26333c; border-radius: 9px; background: #141d25; }
      .stat strong { display: block; font-size: 19px; }
      .stat span { color: #82919a; font-size: 10px; }
      .findings { display: grid; gap: 8px; }
      .finding { padding: 12px; border: 1px solid #2a3740; border-radius: 9px; background: #141d25; }
      .finding-top { display: flex; align-items: center; gap: 8px; }
      .severity { padding: 4px 6px; border-radius: 5px; font-size: 9px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
      .severity.high { color: #ff9a9a; background: #3b2024; }
      .severity.moderate { color: #f2ca78; background: #382e19; }
      .rule-name { color: #dce5e8; font: 700 10px ui-monospace, SFMono-Regular, Menlo, monospace; }
      .finding p { margin: 7px 0 0; color: #a6b3b9; font-size: 11px; line-height: 1.55; }
      .finding .fix { color: #82d9ba; }
      .empty-state { min-height: 210px; display: grid; place-items: center; padding: 20px; border: 1px dashed #34434c; border-radius: 10px; color: #809099; text-align: center; font-size: 12px; line-height: 1.7; }
      .empty-icon { width: 42px; height: 42px; display: grid; place-items: center; margin: 0 auto 10px; border: 1px solid #31423f; border-radius: 13px; color: #71e3b8; background: #15231f; font-size: 20px; }
      .gate { margin-top: 16px; padding: 15px; border: 1px solid #3b382b; border-radius: 10px; background: linear-gradient(135deg, #211e17, #171a1d); }
      .gate-title { display: flex; align-items: center; gap: 8px; color: #f1d38f; font-size: 11px; font-weight: 750; }
      .gate p { margin: 7px 0 12px; color: #a69e8a; font-size: 10px; line-height: 1.6; }
      .gate-output { display: none; max-height: 125px; overflow: auto; margin-top: 10px; padding: 10px; border: 1px solid #34312a; border-radius: 7px; color: #d7cba9; background: #11130f; font: 10px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
      .gate-output.visible { display: block; }
      .disclaimer { margin: 16px 2px 0; color: #74838c; font-size: 10px; line-height: 1.6; }
      .footer { display: flex; justify-content: space-between; gap: 18px; padding: 24px 0 30px; border-top: 1px solid #202b34; color: #7e8d96; font-size: 11px; }
      .footer-links { display: flex; gap: 18px; }
      @media (max-width: 820px) { .workbench { grid-template-columns: 1fr; } .results-body { min-height: 0; } .hero { align-items: flex-start; flex-direction: column; } .hero-badge { margin: 0; } }
      @media (max-width: 560px) { .shell { width: min(100% - 28px, 1180px); } .topbar { height: 62px; } .top-links { gap: 13px; font-size: 11px; } .top-links .network-pill { display: none; } main { padding: 38px 0; } .metrics { gap: 7px; } .metric { padding: 12px 10px; } .metric-value { font-size: 16px; } .metric-value small { display: block; margin-top: 3px; } .panel-head { align-items: flex-start; } .editor-meta { align-items: flex-end; flex-direction: column; } select { max-width: 145px; } .actions .btn { flex: 1; } .footer { align-items: flex-start; flex-direction: column; } }
    </style>
  </head>
  <body>
    <div class="shell">
      <header class="topbar">
        <a class="brand" href="/" aria-label="SecureForce AI home"><span class="brand-mark">S</span><span>SecureForce <span style="color:#76e5bb">AI</span></span></a>
        <nav class="top-links" aria-label="Main navigation">
          <a href="#workbench">Workbench</a>
          <a href="/openapi.json">API docs</a>
          <span class="network-pill"><span class="dot"></span> Tempo testnet</span>
        </nav>
      </header>

      <main>
        <section class="hero">
          <div>
            <div class="eyebrow">Apex security · machine-native payments</div>
            <h1>Find the risk.<br><span>See the payment.</span></h1>
            <p class="intro">Explore a Salesforce Apex scan, then see how an API can request payment exactly when it’s needed. This interactive demo runs on Tempo testnet.</p>
          </div>
          <span class="network-pill hero-badge"><span class="dot"></span> Testnet · no real money</span>
        </section>

        <section class="metrics" aria-label="Service details">
          <div class="metric"><div class="metric-label">Scan price</div><div class="metric-value">$${PRICE_USD} <small>per scan</small></div></div>
          <div class="metric"><div class="metric-label">Payment protocol</div><div class="metric-value">MPP <small>HTTP 402</small></div></div>
          <div class="metric"><div class="metric-label">Scanner mode</div><div class="metric-value">Apex <small>pattern preview</small></div></div>
        </section>

        <section class="workbench" id="workbench" aria-label="Interactive demo">
          <div class="panel">
            <div class="panel-head">
              <div class="panel-title"><span class="step">01</span> Try an Apex sample</div>
              <div class="editor-meta">
                <select id="sample-select" aria-label="Choose sample">
                  <option value="risky">Risky controller</option>
                  <option value="clean">Safer example</option>
                  <option value="callout">Insecure callout</option>
                </select>
                <span>APEX · <span id="line-count">8</span> lines</span>
              </div>
            </div>
            <div class="editor">
              <textarea id="code-input" aria-label="Apex source code" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea>
            </div>
            <div class="editor-foot"><span>✦ Preview runs in this browser</span><span>Source is not uploaded for preview</span></div>
            <div class="actions">
              <button class="btn btn-primary" id="preview-button" type="button">▶ &nbsp;Preview findings</button>
              <button class="btn btn-secondary" id="challenge-shortcut" type="button">↗ &nbsp;Try payment gate</button>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <div class="panel-title"><span class="step">02</span> Scan preview</div>
              <span class="status-pill neutral" id="preview-status"><span class="dot"></span> Ready to explore</span>
            </div>
            <div class="results-body">
              <div class="result-intro">
                <div><h2 id="result-heading">Your findings appear here</h2><p id="result-caption">Choose a sample and preview the local pattern matches.</p></div>
              </div>
              <div id="result-content">
                <div class="empty-state"><div><div class="empty-icon">⌕</div>Run a preview to see matching Apex patterns<br>and suggested next steps.</div></div>
              </div>
              <section class="gate" aria-label="Live payment challenge">
                <div class="gate-title">⚡ Live API · payment required</div>
                <p>This makes an unpaid request to the real scan endpoint. It will show the MPP challenge (HTTP 402); it will not charge you or upload the code in the editor.</p>
                <button class="btn btn-secondary" id="challenge-button" type="button">Request $${PRICE_USD} challenge <span aria-hidden="true">→</span></button>
                <pre class="gate-output" id="challenge-output" role="status" aria-live="polite"></pre>
              </section>
              <p class="disclaimer">Prototype preview uses simple browser-side pattern matching and is not a paid scan or a complete security audit. Don’t paste sensitive source code into this demo.</p>
            </div>
          </div>
        </section>
      </main>

      <footer class="footer">
        <span>SecureForce AI · Apex security demo · Tempo testnet</span>
        <nav class="footer-links" aria-label="Resources"><a href="/health">Health</a><a href="/llms.txt">Usage</a><a href="/openapi.json">OpenAPI</a></nav>
      </footer>
    </div>
    <script>
      (function () {
        var samples = {
          risky: [
            'public without sharing class AccountLookup {',
            '  @AuraEnabled',
            '  public static List<Account> find(String term) {',
            '    String query = \\'SELECT Id FROM Account WHERE Name = \\' + term;',
            '    List<Account> rows = [SELECT Id, Name FROM Account];',
            '    update rows;',
            '    return rows;',
            '  }',
            '}'
          ].join('\\n'),
          clean: [
            'public with sharing class AccountLookup {',
            '  @AuraEnabled',
            '  public static List<Account> find(String term) {',
            '    return [SELECT Id, Name FROM Account WHERE Name = :term WITH USER_MODE];',
            '  }',
            '}'
          ].join('\\n'),
          callout: [
            'public with sharing class PartnerSync {',
            '  public static HttpResponse send() {',
            '    HttpRequest req = new HttpRequest();',
            '    req.setEndpoint(\\'http://partner.example/api\\');',
            '    req.setMethod(\\'GET\\');',
            '    return new Http().send(req);',
            '  }',
            '}'
          ].join('\\n')
        };
        var codeInput = document.getElementById('code-input');
        var sampleSelect = document.getElementById('sample-select');
        var resultContent = document.getElementById('result-content');
        var previewStatus = document.getElementById('preview-status');
        var challengeOutput = document.getElementById('challenge-output');
        var challengeButton = document.getElementById('challenge-button');
        var previewButton = document.getElementById('preview-button');
        var rules = [
          { id: 'SOQL_INJECTION', severity: 'high', test: function (line) { return /['"]\\s*select\\b[^;]*['"]\\s*\\+/i.test(line) && !/escapeSingleQuotes/i.test(line); }, message: 'SOQL is built using string concatenation; input could change the query.', fix: 'Use static SOQL with bind variables or Database.queryWithBinds().' },
          { id: 'WITHOUT_SHARING', severity: 'high', test: function (line) { return /\\bwithout\\s+sharing\\b/i.test(line); }, message: 'This class ignores record-level sharing rules.', fix: 'Prefer with sharing or inherited sharing unless an exception is reviewed.' },
          { id: 'MISSING_SHARING_DECLARATION', severity: 'moderate', test: function (line) { return /^\\s*(public|global)\\s+(virtual\\s+|abstract\\s+)?class\\b/i.test(line) && !/\\bsharing\\b/i.test(line); }, message: 'The class does not explicitly declare a sharing mode.', fix: 'Declare with sharing or inherited sharing explicitly.' },
          { id: 'INSECURE_ENDPOINT', severity: 'high', test: function (line) { return /setEndpoint\\s*\\(\\s*['"]http:\\/\\//i.test(line); }, message: 'The callout uses unencrypted HTTP.', fix: 'Use HTTPS, preferably through a Named Credential.' },
          { id: 'MISSING_FLS_ON_SOQL', severity: 'moderate', test: function (line) { return /\\[\\s*select\\b/i.test(line) && !/with\\s+(user_mode|security_enforced)/i.test(line); }, message: 'Inline SOQL does not show explicit CRUD/FLS enforcement.', fix: 'Use WITH USER_MODE or Security.stripInaccessible().' },
          { id: 'UNCHECKED_DML', severity: 'moderate', test: function (line) { return /^\\s*(insert|update|delete|upsert)\\s+[\\w.()]+\\s*;/i.test(line); }, message: 'DML runs without an explicit user-mode permission check.', fix: 'Use Database DML with AccessLevel.USER_MODE or check object permissions.' }
        ];

        function updateLineCount() {
          document.getElementById('line-count').textContent = String(codeInput.value ? codeInput.value.split('\\n').length : 0);
        }

        function preview() {
          var findings = [];
          var lines = codeInput.value.split(/\\r?\\n/);
          lines.forEach(function (line, index) {
            if (/^\\s*(\\/\\/|\\*|\\/\\*)/.test(line)) return;
            rules.forEach(function (rule) {
              if (rule.test(line)) findings.push({ rule: rule, line: index + 1 });
            });
          });
          var high = findings.filter(function (finding) { return finding.rule.severity === 'high'; }).length;
          var moderate = findings.length - high;
          document.getElementById('result-heading').textContent = findings.length ? findings.length + ' pattern' + (findings.length === 1 ? '' : 's') + ' found' : 'No demo patterns found';
          document.getElementById('result-caption').textContent = lines.length + ' lines checked locally · this is not a paid API scan';
          previewStatus.className = 'status-pill ' + (findings.length ? 'warning' : 'success');
          previewStatus.textContent = findings.length ? high + ' high · ' + moderate + ' moderate' : 'No matches';
          resultContent.replaceChildren();

          var stats = document.createElement('div');
          stats.className = 'stats';
          [
            [String(findings.length), 'Patterns'],
            [String(high), 'High'],
            [String(moderate), 'Moderate']
          ].forEach(function (item) {
            var stat = document.createElement('div');
            stat.className = 'stat';
            var value = document.createElement('strong');
            value.textContent = item[0];
            var label = document.createElement('span');
            label.textContent = item[1];
            stat.append(value, label);
            stats.append(stat);
          });
          resultContent.append(stats);

          if (!findings.length) {
            var clean = document.createElement('div');
            clean.className = 'empty-state';
            clean.textContent = 'No matching demo patterns in this sample. This does not guarantee the code is secure.';
            resultContent.append(clean);
            return;
          }

          var list = document.createElement('div');
          list.className = 'findings';
          findings.forEach(function (finding) {
            var card = document.createElement('article');
            card.className = 'finding';
            var top = document.createElement('div');
            top.className = 'finding-top';
            var severity = document.createElement('span');
            severity.className = 'severity ' + finding.rule.severity;
            severity.textContent = finding.rule.severity;
            var name = document.createElement('span');
            name.className = 'rule-name';
            name.textContent = finding.rule.id;
            var lineNumber = document.createElement('span');
            lineNumber.className = 'rule-name';
            lineNumber.textContent = 'L' + finding.line;
            top.append(severity, name, lineNumber);
            var message = document.createElement('p');
            message.textContent = finding.rule.message;
            var fix = document.createElement('p');
            fix.className = 'fix';
            fix.textContent = 'Suggested fix: ' + finding.rule.fix;
            card.append(top, message, fix);
            list.append(card);
          });
          resultContent.append(list);
        }

        function setChallengeMessage(message, state) {
          challengeOutput.textContent = message;
          challengeOutput.classList.add('visible');
          previewStatus.className = 'status-pill ' + state;
          previewStatus.textContent = state === 'success' ? 'Challenge received' : 'Payment required';
        }

        async function requestChallenge() {
          challengeButton.disabled = true;
          challengeButton.textContent = 'Requesting challenge…';
          challengeOutput.classList.remove('visible');
          try {
            var response = await fetch('/api/scan', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: '{}'
            });
            var payload = await response.json();
            if (response.status === 402) {
              setChallengeMessage('HTTP 402 · Payment Required\\n' + (payload.detail || payload.title || 'The API returned an MPP payment challenge.') + '\\nPrice: $${PRICE_USD} · Tempo testnet · No payment was made.', 'warning');
            } else {
              setChallengeMessage('Unexpected response: HTTP ' + response.status + '\\n' + JSON.stringify(payload), 'neutral');
            }
          } catch (error) {
            setChallengeMessage('Could not reach the scan API. Check your connection and try again.', 'neutral');
          } finally {
            challengeButton.disabled = false;
            challengeButton.innerHTML = 'Request $${PRICE_USD} challenge <span aria-hidden="true">→</span>';
          }
        }

        codeInput.value = samples.risky;
        updateLineCount();
        codeInput.addEventListener('input', updateLineCount);
        sampleSelect.addEventListener('change', function () {
          codeInput.value = samples[sampleSelect.value];
          updateLineCount();
          preview();
        });
        previewButton.addEventListener('click', preview);
        challengeButton.addEventListener('click', requestChallenge);
        document.getElementById('challenge-shortcut').addEventListener('click', function () {
          document.querySelector('.gate').scrollIntoView({ behavior: 'smooth', block: 'center' });
          requestChallenge();
        });
        preview();
      }());
    </script>
  </body>
</html>`);
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'secureforce-ai', priceUsdPerScan: PRICE_USD, network: 'tempo-testnet' });
});

app.get('/llms.txt', (_req, res) => {
  res.type('text/plain').send(
    [
      '# SecureForce AI (prototype)',
      '> Scans Salesforce Apex code for security issues (SOQL injection, sharing, CRUD/FLS, insecure callouts).',
      '',
      `## Pricing`,
      `POST /api/scan costs $${PRICE_USD} per scan, paid with MPP on Tempo testnet (pathUSD or OUSD).`,
      'Unpaid requests return HTTP 402 with a WWW-Authenticate: Payment challenge.',
      '',
      '## Usage',
      'POST /api/scan  JSON body: {"code": "<apex source>"}',
      'Returns JSON findings and a Payment-Receipt header.',
      '',
      '## Free endpoints',
      'GET /health, GET /openapi.json, GET /llms.txt',
      '',
    ].join('\n'),
  );
});

// ---- the paid route --------------------------------------------------------
// Order matters:
//   1) validate input FIRST, so nobody pays for a request we would reject
//   2) payment gate: no valid payment => 402, the handler below never runs
//   3) handler: runs the scan only after payment is verified
function validateScanBody(req: express.Request, res: express.Response, next: express.NextFunction) {
  // Unpaid requests ALWAYS fall through to the payment gate so they get a 402
  // (the MPP spec and the hackathon scanner require this, even for an empty body).
  // Only requests that carry a payment credential are validated, and that happens
  // BEFORE the credential is verified/settled, so a bad body is never charged.
  const auth = req.headers.authorization ?? '';
  if (!/^Payment\s/i.test(auth)) return next();

  const code = req.body?.code;
  if (typeof code !== 'string' || code.trim().length === 0) {
    res.status(400).json({ error: 'invalid_request', message: 'Body must be JSON: {"code": "<apex source>"}' });
    return;
  }
  if (code.length > MAX_CODE_CHARS) {
    res.status(413).json({ error: 'too_large', message: `code must be <= ${MAX_CODE_CHARS} characters` });
    return;
  }
  next();
}

app.post('/api/scan', validateScanBody, pay, (req, res) => {
  const scanId = randomUUID();
  const started = Date.now();
  const result = scanApex(req.body.code as string);
  res.json({
    scanId,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    engine: 'secureforce-prototype-rules',
    ...result,
  });
});

// Payment history: metadata only, never source code.
app.get('/api/payments', (_req, res) => {
  res.json({ count: payments.length, payments: payments.slice(-50).reverse() });
});

// Record every payment mppx has actually verified (receipt comes from mppx, not us).
mppx.onPaymentSuccess(({ receipt, payer }) => {
  payments.push({
    at: new Date().toISOString(),
    receiptRef: String((receipt as { reference?: string }).reference ?? ''),
    payer: payer ?? null,
    amountUsd: PRICE_USD,
  });
  console.log(`[payment] verified payer=${payer ?? 'unknown'} amount=$${PRICE_USD}`);
});

// ---- discovery: generates /openapi.json with x-payment-info + 402 ---------
discovery(app, mppx, {
  info: { title: 'SecureForce AI', version: '0.1.0' },
  routes: [
    {
      handler: pay,
      method: 'post',
      path: '/api/scan',
      summary: 'Scan Apex code for security issues ($0.08)',
      // Declared so agents and scanners know what body to send.
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['code'],
              properties: { code: { type: 'string', maxLength: MAX_CODE_CHARS, description: 'Apex source code' } },
            },
            example: { code: 'public without sharing class Demo { }' },
          },
        },
      },
    },
  ],
});

app.listen(PORT, () => {
  console.log(`SecureForce AI listening on :${PORT}  (${RULE_COUNT} rules, $${PRICE_USD}/scan, Tempo TESTNET)`);
});
