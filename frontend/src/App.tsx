import type { ReactElement } from "react";
import { BrowserRouter, Navigate, Route, Routes, useParams } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import { extensions } from "./extensions";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { AuditLogPage } from "./pages/AuditLog";
import { ApplicationDetailPage } from "./pages/ApplicationDetail";
import { DashboardPage } from "./pages/Dashboard";
import { GroupsPage } from "./pages/Groups";
import { HelpPage } from "./pages/Help";
import { Login } from "./pages/Login";
import { ModelRedirectPage } from "./pages/ModelRedirect";
import { SettingsPage } from "./pages/Settings";
import { Setup } from "./pages/Setup";
import { ThreatKnowledgeBasePage } from "./pages/ThreatKnowledgeBase";

function ProtectedRoute({ children }: { children: ReactElement }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return null;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <AppLayout>{children}</AppLayout>;
}

// Redirect old group URL to new flat list with group filter
function GroupRedirectPage() {
  const { groupId } = useParams<{ groupId: string }>();
  return <Navigate to={`/applications?group=${encodeURIComponent(groupId ?? "ungrouped")}`} replace />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/setup" element={<Setup />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/applications"
        element={
          <ProtectedRoute>
            <GroupsPage />
          </ProtectedRoute>
        }
      />
      <Route path="/applications/groups/:groupId" element={<GroupRedirectPage />} />
      <Route
        path="/applications/:applicationId/runs/:runId"
        element={
          <ProtectedRoute>
            <ApplicationDetailPage />
          </ProtectedRoute>
        }
      />
      {/* URL-addressed tabs: overview, diagram, threats, actions, findings,
          settings, and any a plugin adds. Handled client-side (ApplicationDetail.tsx falls
          back to Overview for an unknown slug), so this is the same element as
          the route above, just with the extra segment. */}
      <Route
        path="/applications/:applicationId/runs/:runId/:tab"
        element={
          <ProtectedRoute>
            <ApplicationDetailPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/models/:applicationId"
        element={
          <ProtectedRoute>
            <ModelRedirectPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/threat-kb"
        element={
          <ProtectedRoute>
            <ThreatKnowledgeBasePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <SettingsPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/audit-log"
        element={
          <ProtectedRoute>
            <AuditLogPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/help/:topic?"
        element={
          <ProtectedRoute>
            <HelpPage />
          </ProtectedRoute>
        }
      />
      {extensions.routes.map((route) => (
        <Route
          key={route.path}
          path={route.path}
          element={<ProtectedRoute>{route.element as ReactElement}</ProtectedRoute>}
        />
      ))}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
