/* global process */
import { defineConfig } from '@playwright/test';

const port = Number(process.env.SHIELD_PORT || 8799);
const executablePath = process.env.PW_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: 'e2e',
  workers: 1,
  reporter: [['line'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'on',
    screenshot: 'on',
    launchOptions: executablePath ? { executablePath } : {},
  },
  webServer: {
    command: `node ./node_modules/wrangler/bin/wrangler.js dev --config shield/example/wrangler.jsonc --local --ip 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/`,
    timeout: 120_000,
    reuseExistingServer: false,
  },
});
