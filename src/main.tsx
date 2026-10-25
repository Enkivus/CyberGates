import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ToastProvider } from "./components/ToastProvider";
import { applyTheme, initialTheme } from "./lib/theme";
import "./styles/styles.css";

applyTheme(initialTheme());

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ToastProvider>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </ToastProvider>
  </StrictMode>,
);
