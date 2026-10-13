import { useSyncExternalStore } from 'react';
import { getState, subscribe } from '@/api/session';
import { can, type Capability } from '@/lib/permissions';

export const useSession = () => useSyncExternalStore(subscribe, getState, getState);

/** The signed-in person and what they may do. `can` is the only place the interface asks about roles. */
export function useAuth() {
  const s = useSession();
  return { user: s.user, status: s.status, reason: s.reason, can: (cap: Capability) => can(s.user, cap) };
}
