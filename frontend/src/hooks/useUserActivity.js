import { useCallback, useEffect, useState } from 'react';
import { userPortalService } from '../services/userPortalService';

export function useUserActivity() {
  const [activity, setActivity] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);

    userPortalService.getActivity()
      .then((result) => {
        if (active) setActivity(result);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message || 'Could not load your security activity.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [refreshVersion]);

  const refresh = useCallback(() => {
    setRefreshVersion((version) => version + 1);
  }, []);

  return {
    activity,
    loading,
    error,
    refresh,
  };
}
