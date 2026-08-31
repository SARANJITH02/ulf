import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './theme/ThemeContext';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { UnknownLogLab } from './pages/UnknownLogLab';
import { LiveStreamViewer } from './pages/LiveStreamViewer';
import { ParserManager } from './pages/ParserManager';
import { RulesConfig } from './pages/RulesConfig';
import { SiemExporter } from './pages/SiemExporter';

// Simple route guard
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const token = localStorage.getItem('ulpf-token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="lab" element={<UnknownLogLab />} />
            <Route path="stream" element={<LiveStreamViewer />} />
            <Route path="parsers" element={<ParserManager />} />
            <Route path="rules" element={<RulesConfig />} />
            <Route path="export" element={<SiemExporter />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
};
