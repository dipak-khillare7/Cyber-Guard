export const USER_PORTAL_ROLES = ['VIEWER', 'ANALYST', 'ADMIN'];
export const STAFF_PORTAL_ROLES = ['ANALYST', 'ADMIN'];

export function getPortalOptions(role, permissions = []) {
  const permissionList = Array.isArray(permissions) ? permissions : [];
  const options = [];

  if (role === 'VIEWER' && permissionList.includes('portal:normal')) {
    options.push({ id: 'user', label: 'Normal User Portal', path: '/user/dashboard' });
  }
  if (
    role === 'ANALYST'
    && permissionList.includes('portal:normal')
    && permissionList.includes('portal:analyst')
  ) {
    options.push(
      { id: 'user', label: 'Normal User Portal', path: '/user/dashboard' },
      { id: 'analyst', label: 'SOC Analyst Dashboard', path: '/analyst/dashboard' },
    );
  }
  if (
    role === 'ADMIN'
    && permissionList.includes('portal:normal')
    && permissionList.includes('portal:analyst')
  ) {
    options.push(
      { id: 'user', label: 'Normal User Portal', path: '/user/dashboard' },
      { id: 'analyst', label: 'SOC / Admin Dashboard', path: '/dashboard' },
    );
  }

  return options;
}

export function getPortalHome(role, selectedPortal) {
  if (role === 'VIEWER') return '/user/dashboard';
  if (role === 'ANALYST') {
    return selectedPortal === 'user' ? '/user/dashboard' : '/analyst/dashboard';
  }
  if (role === 'ADMIN') {
    return selectedPortal === 'user' ? '/user/dashboard' : '/dashboard';
  }
  return '/login';
}
