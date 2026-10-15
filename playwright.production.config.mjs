import { defineConfig } from '@playwright/test';

const port = Number(process.env.PROTECT_PROD_TEST_PORT || 8800);

export default defineConfig({
  testDir: 'e2e-production',
  workers: 1,
  reporter: [['line'], ['html', { open: 'never', outputFolder: 'playwright-production-report' }]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'on',
    screenshot: 'on',
  },
  webServer: {
    command: `npx wrangler dev --config wrangler.jsonc --local --ip 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/`,
    timeout: 120_000,
    reuseExistingServer: false,
  },
});
