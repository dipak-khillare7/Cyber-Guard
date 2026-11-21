import test from 'node:test';
import assert from 'node:assert/strict';
import { validateWebsiteUrl } from '../src/utils/websiteUrl.js';

test('accepts complete HTTP and HTTPS website URLs', () => {
  assert.equal(validateWebsiteUrl('https://example.com/path'), '');
  assert.equal(validateWebsiteUrl('http://example.com'), '');
});

test('rejects missing URLs, unsupported schemes, and embedded credentials', () => {
  assert.match(validateWebsiteUrl(''), /Enter a website URL/);
  assert.match(validateWebsiteUrl('ftp://example.com'), /Only HTTP and HTTPS/);
  assert.match(validateWebsiteUrl('https://user:pass@example.com'), /without embedded login credentials/);
});

test('requires explicit HTTP(S) syntax and rejects parser-ambiguous URLs', () => {
  assert.match(validateWebsiteUrl('example.com'), /Include http:\/\/ or https:\/\//);
  assert.match(validateWebsiteUrl('https://example.com\\@evil.com'), /backslashes/);
  assert.match(validateWebsiteUrl('https://example.com/a b'), /spaces/);
  assert.match(validateWebsiteUrl('https://@example.com'), /without embedded login credentials/);
});

test('accepts Unicode domains that can be normalized by the browser', () => {
  assert.equal(validateWebsiteUrl('https://münich.example.org/path?q=1'), '');
});
