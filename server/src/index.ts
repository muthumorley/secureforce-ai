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
