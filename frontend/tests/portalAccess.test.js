import test from 'node:test';
import assert from 'node:assert/strict';
import { getPortalHome, getPortalOptions } from '../src/utils/portalAccess.js';

test('Viewer accounts only receive the Normal User Portal', () => {
  assert.deepEqual(getPortalOptions('VIEWER'), []);
  assert.deepEqual(
    getPortalOptions('VIEWER', ['portal:normal']),
    [{ id: 'user', label: 'Normal User Portal', path: '/user/dashboard' }],
  );
  assert.deepEqual(getPortalOptions('VIEWER', ['portal:analyst', 'portal:admin']), []);
  assert.equal(getPortalHome('VIEWER', 'analyst'), '/user/dashboard');
});

test('Analysts can select the Normal User or SOC Analyst Portal', () => {
  assert.deepEqual(
    getPortalOptions('ANALYST', ['portal:normal', 'portal:analyst']).map(({ id, path }) => ({ id, path })),
    [
      { id: 'user', path: '/user/dashboard' },
      { id: 'analyst', path: '/analyst/dashboard' },
    ],
  );
  assert.equal(getPortalHome('ANALYST', 'user'), '/user/dashboard');
  assert.equal(getPortalHome('ANALYST', 'analyst'), '/analyst/dashboard');
  assert.equal(getPortalHome('ANALYST', 'unknown'), '/analyst/dashboard');
});

test('Admins retain the existing SOC/Admin routes when restoring staff portal state', () => {
  const options = getPortalOptions('ADMIN', ['portal:normal', 'portal:analyst', 'portal:admin']);
  assert.deepEqual(options.map(({ id }) => id), ['user', 'analyst']);
  assert.equal(options[1].path, '/dashboard');
  assert.equal(getPortalHome('ADMIN', 'user'), '/user/dashboard');
  assert.equal(getPortalHome('ADMIN', 'analyst'), '/dashboard');
});

test('Unknown roles never restore a protected portal', () => {
  assert.deepEqual(getPortalOptions('GUEST'), []);
  assert.deepEqual(
    getPortalOptions('GUEST', ['portal:normal', 'portal:analyst', 'portal:admin']),
    [],
  );
  assert.equal(getPortalHome('GUEST', 'analyst'), '/login');
});

test('Analyst and Admin workspaces are hidden without the required backend permissions', () => {
  assert.deepEqual(getPortalOptions('ANALYST', ['portal:normal']), []);
  assert.deepEqual(getPortalOptions('ADMIN', ['portal:normal']), []);
});
