export function getAuthenticatedHome(role) {
  if (role === 'ADMIN') return '/dashboard';
  if (role === 'ANALYST') return '/analyst/dashboard';
  return '/unauthorized';
}
