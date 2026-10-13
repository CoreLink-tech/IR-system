import type { ReactNode } from 'react';

/** A small set of icons, drawn here so nothing loads from another site. Decorative: always paired with words. */
const base = { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2.2, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true, focusable: false };
const make = (d: ReactNode) => function Icon() { return <svg {...base}>{d}</svg>; };

export const IconShield = make(<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />);
export const IconAlert = make(<><path d="M12 3l10 18H2z" /><path d="M12 10v5M12 18.5v.01" /></>);
export const IconOctagon = make(<><path d="M8 3h8l5 5v8l-5 5H8l-5-5V8z" /><path d="M12 8v5M12 16.5v.01" /></>);
export const IconInfo = make(<><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7.5v.01" /></>);
export const IconCheck = make(<path d="M4 12.5l5 5L20 6.5" />);
export const IconEye = make(<><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>);
export const IconBan = make(<><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></>);
export const IconClock = make(<><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>);
export const IconUser = make(<><circle cx="12" cy="8" r="4" /><path d="M4 21c1-4 4-6 8-6s7 2 8 6" /></>);
export const IconX = make(<path d="M6 6l12 12M18 6L6 18" />);
export const IconSearch = make(<><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></>);
export const IconPlay = make(<path d="M7 4l13 8-13 8z" />);
export const IconFlag = make(<><path d="M5 21V4" /><path d="M5 4h12l-2 4 2 4H5" /></>);
