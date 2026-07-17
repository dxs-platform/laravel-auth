import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { startFakeIdp } from '../support/fake-idp.mjs';
import { startConsumer, waitForUrl } from '../support/processes.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = process.env.E2E_FIXTURES_DIR
  ? path.resolve(process.env.E2E_FIXTURES_DIR)
  : path.resolve(here, '../fixtures');
let idp;
let consumerA;
let consumerB;

test.beforeAll(async () => {
  for (const consumer of ['downstream-a', 'downstream-b']) {
    execFileSync('php', ['artisan', 'cache:clear'], { cwd: path.join(fixtures, consumer) });
  }
  idp = await startFakeIdp();
  consumerA = startConsumer(path.join(fixtures, 'downstream-a'), 9401);
  consumerB = startConsumer(path.join(fixtures, 'downstream-b'), 9402);
  await Promise.all([
    waitForUrl('http://downstream-a.localhost:9401'),
    waitForUrl('http://downstream-b.localhost:9402'),
  ]);
});

test.afterAll(async () => {
  consumerA?.stop();
  consumerB?.stop();
  await idp?.close();
});

async function login(page, origin, expectedService, organization = idp.organizationA) {
  await page.goto(origin);
  const authorizeRequest = page.waitForRequest((request) => request.url().includes('/sso/authorize'));
  await page.getByRole('link', { name: 'Start SSO login' }).click();
  const request = await authorizeRequest;
  const authorize = new URL(request.url());
  expect(authorize.searchParams.get('organization_context_id')).toBe(organization);
  expect(authorize.searchParams.get('state')).toHaveLength(40);
  expect(authorize.searchParams.get('nonce')).toHaveLength(40);
  expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorize.searchParams.get('code_challenge')).not.toBe('');
  await expect(page.getByRole('heading')).toHaveText(`Authorize ${expectedService}`);
  await page.getByRole('button', { name: 'Continue as E2E User' }).click();
  await expect(page).toHaveURL(new RegExp(`${origin}/protected`));
  await expect(page.getByTestId('service')).toHaveText(expectedService);
  await expect(page.getByTestId('organization')).toHaveText(organization);
  return request.url();
}

test('real browser login and bearer permission contract work for two isolated consumers', async ({ page, context }) => {
  await login(page, 'http://downstream-a.localhost:9401', 'consumer-a');
  await page.getByRole('link', { name: 'Load permissions' }).click();
  await expect(page.getByText('consumer-a.dashboard.view')).toBeVisible();

  await login(page, 'http://downstream-b.localhost:9402', 'consumer-b', idp.organizationB);
  await page.getByRole('link', { name: 'Load permissions' }).click();
  await expect(page.getByText('consumer-b.dashboard.view')).toBeVisible();

  const cookies = await context.cookies();
  const tokens = cookies.filter((cookie) => cookie.name === 'dxs_e2e_token');
  expect(tokens).toHaveLength(2);
  expect(new Set(tokens.map((cookie) => cookie.domain))).toEqual(new Set(['downstream-a.localhost', 'downstream-b.localhost']));
  for (const cookie of tokens) {
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('Lax');
  }
});

test('two tabs keep independent state and PKCE transactions', async ({ context }) => {
  const first = await context.newPage();
  const second = await context.newPage();
  await first.goto('http://downstream-a.localhost:9401');
  await second.goto('http://downstream-a.localhost:9401');
  await first.getByRole('link', { name: 'Start SSO login' }).click();
  await second.getByRole('link', { name: 'Start SSO login' }).click();
  await second.getByRole('button', { name: 'Continue as E2E User' }).click();
  await expect(second.getByTestId('service')).toHaveText('consumer-a');
  await first.getByRole('button', { name: 'Continue as E2E User' }).click();
  await expect(first.getByTestId('service')).toHaveText('consumer-a');
});

test('wrong state, callback replay, and organization-claim substitution fail closed', async ({ page }) => {
  const responses = [];
  page.on('response', (response) => {
    if (response.url().includes('/auth/callback')) responses.push(response.url());
  });
  await login(page, 'http://downstream-a.localhost:9401', 'consumer-a');
  const callback = responses.at(-1);
  expect(callback).toBeTruthy();
  const replay = await page.goto(callback);
  expect(replay.status()).toBe(500);
  await expect(page.getByText(/state mismatch/i)).toBeVisible();

  const wrongState = await page.goto('http://downstream-a.localhost:9401/auth/callback?code=unused&state=wrong');
  expect(wrongState.status()).toBe(500);
  await expect(page.getByText(/state mismatch/i)).toBeVisible();

  await page.goto('http://downstream-a.localhost:9401');
  await page.getByRole('link', { name: 'Start SSO login' }).click();
  const tampered = await Promise.all([
    page.waitForResponse((response) => response.url().includes('/auth/callback')),
    page.getByRole('button', { name: 'Tamper organization claim' }).click(),
  ]);
  expect(tampered[0].status()).toBe(500);
  await expect(page.getByText(/organization context (does not match|mismatch)/i)).toBeVisible();
});

test('IdP back-channel logout reaches both running consumers and revokes both browser sessions', async ({ context }) => {
  const consumerAPage = await context.newPage();
  const consumerBPage = await context.newPage();
  await login(consumerAPage, 'http://downstream-a.localhost:9401', 'consumer-a');
  await login(consumerBPage, 'http://downstream-b.localhost:9402', 'consumer-b', idp.organizationB);

  expect(await idp.deliverBackChannelLogout()).toEqual([
    { audience: 'consumer-a', status: 200 },
    { audience: 'consumer-b', status: 200 },
  ]);

  const protectedStatus = (page, origin) => page.evaluate(async (url) => {
    const response = await fetch(url, { headers: { accept: 'application/json' } });
    return response.status;
  }, `${origin}/protected`);

  expect(await protectedStatus(consumerAPage, 'http://downstream-a.localhost:9401')).toBe(401);
  expect(await protectedStatus(consumerBPage, 'http://downstream-b.localhost:9402')).toBe(401);
});
