import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

test('local Worker: founder authentication, evidence match, mismatch and logout', async ({ page, baseURL }) => {
  expect(baseURL).toBe('https://127.0.0.1:8801');
  await page.goto('/founder/medusa');
  await expect(page).toHaveURL(baseURL+'/founder');
  await page.getByLabel('Email').fill('fictional@example.invalid');
  await page.getByLabel('Password', {exact:true}).fill('fictional-local-medusa-test');
  await page.getByRole('button',{name:'Enter the control room'}).click();
  await expect(page).toHaveURL(baseURL+'/founder/room');
  const session = (await page.context().cookies()).find(c=>c.name==='pf_session');
  expect(session).toMatchObject({httpOnly:true,secure:true,sameSite:'Strict',path:'/founder'});
  const review = await page.goto('/founder/medusa');
  expect(review.status()).toBe(200);
  expect(review.headers()['referrer-policy']).toBe('same-origin');
  await expect(page.getByRole('heading',{name:'Evidence review'})).toBeVisible();

  const source = 'Fictional evidence example. The document is ready for review.';
  const hash = createHash('sha256').update(source).digest('hex');
  async function submit(expected) {
    await page.getByLabel('Evidence text').fill(source);
    await page.getByLabel('Expected SHA-256 of submitted text').fill(expected);
    await page.getByLabel('Exact quotation (at least 12 characters)').fill('The document is ready for review.');
    const [response] = await Promise.all([
      page.waitForResponse(r=>r.url()===baseURL+'/founder/medusa' && r.request().method()==='POST'),
      page.getByRole('button',{name:'Review evidence'}).click(),
    ]);
    expect(response.request().headers().origin).toBe(baseURL);
    expect(response.status()).toBe(200);
  }
  await submit(hash);
  await expect(page.getByRole('heading',{name:'MATCH',exact:true})).toBeVisible();
  await expect(page.getByText('No independent truth verification or execution authority.')).toBeVisible();
  await expect(page.locator('textarea[name="source"]')).toHaveValue('');
  await submit('0'.repeat(64));
  await expect(page.getByRole('heading',{name:'MISMATCH',exact:true})).toBeVisible();
  const crossOrigin = await page.request.post('/founder/medusa',{
    headers:{origin:'https://fictional.invalid'},
    form:{source,expected:hash,quote:'The document is ready for review.'}
  });
  expect(crossOrigin.status()).toBe(403);
  await page.goto('/founder/room');
  await page.getByRole('button',{name:'Sign out'}).click();
  await page.goto('/founder/medusa');
  await expect(page).toHaveURL(baseURL+'/founder');
});
