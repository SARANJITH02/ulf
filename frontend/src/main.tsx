import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import './styles/index.css';

// Seed default token if demo/standalone mode for instant exploration
if (!localStorage.getItem('ulpf-token')) {
  // Let user login first or use quick presets
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
