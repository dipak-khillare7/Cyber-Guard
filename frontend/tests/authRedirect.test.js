import test from 'node:test';
import assert from 'node:assert/strict';
import { getAuthenticatedHome } from '../src/utils/authRedirect.js';

test('Analysts and Admins go directly to their authorized SOC dashboard', () => {
  assert.equal(getAuthenticatedHome('ANALYST'), '/analyst/dashboard');
  assert.equal(getAuthenticatedHome('ADMIN'), '/dashboard');
});

test('legacy Viewer and unknown roles go to Access Denied', () => {
  assert.equal(getAuthenticatedHome('VIEWER'), '/unauthorized');
  assert.equal(getAuthenticatedHome('GUEST'), '/unauthorized');
});
