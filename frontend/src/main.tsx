import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./theme.css";
import { App } from "./App";
import { fetchCapabilities } from "./api/capabilities";
import { applyCapabilities, hasExtensions } from "./extensions";
import { setAvailableMethodologies } from "./methodology";
import { initTheme } from "./theme";

initTheme();

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("#root element not found");
}

async function start(root: HTMLElement) {
  // The methodologies on offer come from the server; if it cannot be read, only the built-in STRIDE is shown.
  const capabilities = await fetchCapabilities().catch(() => null);
  setAvailableMethodologies(capabilities?.methodologies);
  if (hasExtensions()) {
    // A plugin frontend is built in: show it only if the backend actually runs the plugin's features.
    applyCapabilities(capabilities);
  }
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void start(rootElement);
