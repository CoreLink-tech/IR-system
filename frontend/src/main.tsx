import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import { loadConfig } from './lib/config';
import { bootstrap, startCrossTab } from './api/session';
import { makeQueryClient } from './api/hooks';
import { TimeProvider } from './lib/time';
import './styles/global.css';

async function start() {
  await loadConfig();
  startCrossTab();
  const queryClient = makeQueryClient();
  // Resume the session from the cookie, if there is one, before showing anything.
  void bootstrap();
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <TimeProvider>
          <BrowserRouter><App /></BrowserRouter>
        </TimeProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}
void start();
