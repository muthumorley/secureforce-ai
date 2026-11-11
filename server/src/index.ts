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
    <meta name="theme-color" content="#101923">
    <title>SecureForce AI — Apex security scans</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #101923; color: #edf4f5; }
      * { box-sizing: border-box; }
      body { margin: 0; min-height: 100vh; background: radial-gradient(ellipse at 75% 0%, #173c3b 0, transparent 38%), #101923; }
      main { width: min(940px, calc(100% - 40px)); margin: 0 auto; padding: 72px 0 64px; }
      .eyebrow { color: #66e0b2; font-size: 13px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
      h1 { max-width: 720px; margin: 18px 0; font-size: clamp(42px, 8vw, 72px); line-height: 1.02; letter-spacing: -.055em; }
      h1 span { color: #66e0b2; }
      .intro { max-width: 650px; color: #b7c5ca; font-size: 18px; line-height: 1.7; }
      .card { margin-top: 40px; padding: 28px; border: 1px solid #2b3d48; border-radius: 16px; background: #15212b; box-shadow: 0 20px 60px #0003; }
      h2 { margin: 0 0 12px; font-size: 20px; }
      p { color: #b7c5ca; line-height: 1.65; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      pre { overflow-x: auto; margin: 18px 0 0; padding: 18px; border-radius: 10px; background: #0c141b; color: #d7e8e7; font-size: 13px; line-height: 1.7; }
      .links { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 26px; }
      a { color: #66e0b2; }
      .links a { padding: 11px 15px; border: 1px solid #3c635c; border-radius: 9px; font-weight: 650; text-decoration: none; }
      .links a:hover { background: #1b3535; }
      .note { margin-top: 20px; color: #90a2a9; font-size: 13px; }
      @media (max-width: 600px) { main { padding-top: 48px; } .card { padding: 20px; } }
    </style>
  </head>
  <body>
    <main>
      <div class="eyebrow">SecureForce AI · Tempo testnet</div>
      <h1>Apex security scans, <span>paid per scan.</span></h1>
      <p class="intro">A demo API that checks Salesforce Apex for common security patterns and charges $${PRICE_USD} per scan using the Machine Payments Protocol (MPP). Testnet only—no real-money payments.</p>

      <section class="card" aria-labelledby="demo-title">
        <h2 id="demo-title">See the payment gate</h2>
        <p>Try a scan without payment to see the HTTP 402 MPP challenge. The scan runs only after a valid testnet payment.</p>
        <pre><code>curl -i -X POST https://secureforce-ai-production.up.railway.app/api/scan \\
  -H 'content-type: application/json' \\
  -d '{"code":"public without sharing class Demo { }"}'</code></pre>
        <p>To complete the testnet payment flow, use an MPP-compatible client with a funded Tempo testnet wallet:</p>
        <pre><code>npx mppx https://secureforce-ai-production.up.railway.app/api/scan --network testnet \\
  -J '{"code":"public without sharing class Demo { }"}'</code></pre>
        <div class="links">
          <a href="/health">Service health</a>
          <a href="/llms.txt">API usage</a>
          <a href="/openapi.json">OpenAPI</a>
        </div>
        <p class="note">Prototype scanner: pattern-based demonstration, not a complete security audit. Don’t submit sensitive source code.</p>
      </section>
    </main>
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
