/**
 * Malcolm Copilot — Application Entry Point
 *
 * Mounts the MalcolmCopilot component into the DOM.
 * The component is fully self-contained (no external CSS, no router needed).
 */
import React from 'react';
import ReactDOM from 'react-dom/client';
import MalcolmCopilot from './App.jsx';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <MalcolmCopilot />
  </React.StrictMode>
);
