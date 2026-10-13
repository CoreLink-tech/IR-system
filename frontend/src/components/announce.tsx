import { useEffect, useState } from 'react';

/** A polite screen-reader announcement for things that change without moving focus (saved, copied, refreshed). */
let listener: ((msg: string) => void) | null = null;
export function announce(message: string) { listener?.(message); }

export function Announcer() {
  const [msg, setMsg] = useState('');
  useEffect(() => {
    listener = (m) => { setMsg(''); setTimeout(() => setMsg(m), 30); };
    return () => { listener = null; };
  }, []);
  return <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{msg}</div>;
}
