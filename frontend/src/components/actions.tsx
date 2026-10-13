import { useState } from 'react';
import { Button } from './ui';
import { announce } from './announce';

/** Saving a file, copying text and printing only ever happen on an explicit click. */
export function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.rel = 'noopener';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function CopyButton({ text, label = 'Copy', onGetText }: { text?: string; label?: string; onGetText?: () => Promise<string> }) {
  const [state, setState] = useState<'idle' | 'busy' | 'done' | 'failed'>('idle');
  const click = async () => {
    setState('busy');
    try {
      const value = onGetText ? await onGetText() : text ?? '';
      await navigator.clipboard.writeText(value);
      setState('done'); announce('Copied to the clipboard');
    } catch { setState('failed'); announce('Could not copy. Select the text and copy it by hand.'); }
    setTimeout(() => setState('idle'), 2500);
  };
  return <Button onClick={click} busy={state === 'busy'}>{state === 'done' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}</Button>;
}

export function DownloadTextButton({ filename, onGetText, label = 'Download text' }: { filename: string; onGetText: () => Promise<string>; label?: string }) {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const click = async () => {
    setBusy(true); setFailed(false);
    try { downloadText(filename, await onGetText()); } catch { setFailed(true); } finally { setBusy(false); }
  };
  return <><Button onClick={click} busy={busy}>{label}</Button>{failed && <span className="error-text" role="alert">Download failed. Try again.</span>}</>;
}

export const PrintButton = ({ label = 'Print or save as PDF' }: { label?: string }) => <Button onClick={() => window.print()}>{label}</Button>;
