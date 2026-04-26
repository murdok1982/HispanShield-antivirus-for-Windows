import { createBrowserRouter } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { Dashboard } from "@/pages/Dashboard";
import { Threats } from "@/pages/Threats";
import { Scan } from "@/pages/Scan";
import { Quarantine } from "@/pages/Quarantine";
import { Processes } from "@/pages/Processes";
import { Connections } from "@/pages/Connections";
import { ThreatIntel } from "@/pages/ThreatIntel";
import { Logs } from "@/pages/Logs";
import { Settings } from "@/pages/Settings";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "threats", element: <Threats /> },
      { path: "scan", element: <Scan /> },
      { path: "quarantine", element: <Quarantine /> },
      { path: "processes", element: <Processes /> },
      { path: "connections", element: <Connections /> },
      { path: "intel", element: <ThreatIntel /> },
      { path: "logs", element: <Logs /> },
      { path: "settings", element: <Settings /> },
    ],
  },
]);
