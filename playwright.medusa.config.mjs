import { defineConfig } from '@playwright/test';
import { pbkdf2Sync, randomBytes } from 'node:crypto';

// This fixture is ONLY for an isolated loopback Wrangler dev process.
// Never deploy these credentials or bind remote resources.
const port = 8801;
const salt = '0102030405060708';
const hash = pbkdf2Sync('fictional-local-medusa-test', Buffer.from(salt,'hex'), 1000, 32, 'sha256').toString('hex');
const session = randomBytes(32).toString('hex');
const shield = randomBytes(32).toString('hex');
const origin = `https://127.0.0.1:${port}`;
export default defineConfig({
  testDir: 'e2e-medusa',
  workers: 1,
  reporter: [['line'], ['html', { open:'never', outputFolder:'playwright-medusa-report' }]],
  use: { baseURL:origin, ignoreHTTPSErrors:true, trace:'on', screenshot:'on' },
  webServer: {
    command: `npx --yes wrangler@4.151.0 dev --config wrangler.jsonc --local --local-protocol https --ip 127.0.0.1 --port ${port} --var FOUNDER_EMAIL:fictional@example.invalid FOUNDER_SALT:${salt} FOUNDER_ITERS:1000 FOUNDER_PASSWORD_HASH:${hash} SESSION_SECRET:${session} SHIELD_SECRET:${shield}`,
    url: origin+'/', ignoreHTTPSErrors:true, timeout:120000, reuseExistingServer:false,
  },
});
