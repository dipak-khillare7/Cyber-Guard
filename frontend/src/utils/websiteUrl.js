export function validateWebsiteUrl(value) {
  if (value !== value.trim()) return 'Remove leading or trailing spaces from the URL.';
  const input = value;
  if (!input) return 'Enter a website URL.';
  if (input.includes('\\') || /\s|[\u0000-\u001f]/u.test(input)) {
    return 'Enter a URL without spaces, backslashes, or control characters.';
  }
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(input) && !/^https?:\/\//i.test(input)) {
    return 'Only HTTP and HTTPS website URLs are supported.';
  }
  if (!/^https?:\/\//i.test(input)) {
    return 'Include http:// or https:// in the website URL.';
  }

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    return 'Enter a complete URL, such as https://example.com.';
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return 'Only HTTP and HTTPS website URLs are supported.';
  }
  if (
    !parsed.hostname
    || parsed.username
    || parsed.password
    || /^[a-z][a-z\d+.-]*:\/\/[^/?#]*@/i.test(input)
  ) {
    return 'Enter a website URL without embedded login credentials.';
  }
  return '';
}
