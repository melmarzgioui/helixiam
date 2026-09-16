import React from "react";
import { createRoot } from "react-dom/client";
import { AccountApp } from "./AccountApp";
import { LocaleProvider } from "../i18n/LocaleContext";
import "../styles/tokens.css";
import "../styles/components.css";

createRoot(document.getElementById("account-root")!).render(
  <React.StrictMode>
    <LocaleProvider>
      <AccountApp />
    </LocaleProvider>
  </React.StrictMode>
);
