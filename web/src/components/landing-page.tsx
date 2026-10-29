'use client';

import { useState } from 'react';
import Link from 'next/link';

const apkPath = '/ir-system.apk';

function GetApp({ className = '' }: { className?: string }) {
  return <a className={`landing-button landing-button-primary ${className}`} href={apkPath} download>Get App <span aria-hidden="true">↓</span></a>;
}

export default function LandingPage({ hideGetApp }: { hideGetApp: boolean }) {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <main className="landing-shell">
      <header className="landing-nav">
        <Link className="landing-brand" href="/" aria-label="Watcher home">
          <span className="brand-mark">W</span><span>Watcher</span>
        </Link>
        <nav className="landing-nav-links" aria-label="Main navigation">
          <a href="#capabilities">Capabilities</a><Link href="/sign-in">Sign in</Link>
        </nav>
        {!hideGetApp && <div className="landing-desktop-cta"><GetApp /></div>}
        <button className="landing-menu-toggle" type="button" aria-label={menuOpen ? 'Close menu' : 'Open menu'} aria-expanded={menuOpen} onClick={() => setMenuOpen(v => !v)}>
          <span></span><span></span><span></span>
        </button>
        {menuOpen && <nav className="landing-mobile-menu" aria-label="Mobile navigation">
          <a href="#capabilities" onClick={() => setMenuOpen(false)}>Capabilities</a>
          <Link href="/sign-in" onClick={() => setMenuOpen(false)}>Sign in</Link>
          {!hideGetApp && <GetApp className="mobile-get-app" />}
        </nav>}
      </header>

      <section className="landing-hero">
        <div className="hero-copy">
          <div className="eyebrow"><span className="status-pulse" /> SECURITY OPERATIONS FOR COMMERCE</div>
          <h1>Know what’s happening.<br /><span>Stop what shouldn’t.</span></h1>
          <p className="hero-lede">Incident response and security monitoring built for e-commerce sites. Catch suspicious activity, contain threats, and keep your storefront moving.</p>
          <div className="hero-actions">
            <Link className="landing-button landing-button-primary" href="/sign-in">Open security dashboard <span aria-hidden="true">↗</span></Link>
            {!hideGetApp && <GetApp />}
          </div>
          <div className="hero-note"><span className="note-dot" /> API-driven protection. A clear view of every incident.</div>
        </div>
        <div className="console-card" aria-label="Illustrative security operations dashboard preview">
          <div className="console-top"><div className="window-dots"><i></i><i></i><i></i></div><span>IR-SYSTEM / LIVE MONITOR</span><span className="console-live"><b></b> ACTIVE</span></div>
          <div className="console-content">
            <div className="console-heading"><div><small>THREAT OVERVIEW</small><h2>Storefront signals</h2></div><span className="console-tag">24H</span></div>
            <div className="metric-row"><div className="metric-box"><small>EVENTS RECEIVED</small><strong>1,284</strong><span className="metric-good">↑ monitored</span></div><div className="metric-box"><small>OPEN INCIDENTS</small><strong className="metric-alert">03</strong><span className="metric-warn">Requires review</span></div></div>
            <div className="chart-panel"><div className="chart-label"><span>Request activity</span><span>LAST 6 HOURS</span></div><div className="chart-bars" aria-hidden="true">{[28,40,33,58,45,65,49,72,54,88,64,46,78,57,95,69,82,51,73,43,61,87,55,74,48,67].map((height,i)=><i key={i} style={{height:`${height}%`}} />)}</div><div className="chart-axis"><span>06:00</span><span>09:00</span><span>12:00</span><span>15:00</span></div></div>
            <div className="incident-row"><span className="incident-icon">!</span><div><b>Credential stuffing pattern</b><small>Repeated login failures · 2 min ago</small></div><span className="severity-pill">HIGH</span></div>
            <div className="incident-row"><span className="incident-icon blocked">×</span><div><b>Automated checkout probes</b><small>Source added to blocklist · 8 min ago</small></div><span className="severity-pill critical">CRITICAL</span></div>
          </div>
        </div>
        <div className="hero-grid" aria-hidden="true"></div>
      </section>

      <section className="capabilities" id="capabilities">
        <div className="section-heading"><div className="eyebrow">BUILT FOR FAST RESPONSE</div><h2>Signals in. Threats contained.</h2><p>Connect your storefront to a focused response workflow, without burying your team in noise.</p></div>
        <div className="feature-grid">
          <article className="feature-card"><span className="feature-number">01 / INGEST</span><div className="feature-icon">↯</div><h3>Events API</h3><p>Send security events from your e-commerce stack and bring activity into one reliable incident timeline.</p><a href="/sign-in">Explore the dashboard <span>↗</span></a></article>
          <article className="feature-card"><span className="feature-number">02 / CONTAIN</span><div className="feature-icon shield">⌑</div><h3>Blocklist polling</h3><p>Poll managed blocklists to keep known hostile sources out, with controls to review and manage decisions.</p><a href="/sign-in">Manage protection <span>↗</span></a></article>
          <article className="feature-card"><span className="feature-number">03 / RESPOND</span><div className="feature-icon">⌘</div><h3>Incident dashboard</h3><p>Investigate suspicious IPs, prioritize incidents, and track response status from detection to resolution.</p><a href="/sign-in">Sign in to Watcher <span>↗</span></a></article>
        </div>
      </section>
      <footer className="landing-footer"><Link className="landing-brand" href="/"><span className="brand-mark">W</span><span>Watcher</span></Link><span>Incident response for the storefronts you run.</span><Link href="/sign-in">Dashboard sign in ↗</Link></footer>
    </main>
  );
}
