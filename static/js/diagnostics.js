/* Diagnostics frontend safety wrapper. */
import { renderDiagnosticsPanel } from "./toolSafety.js";

const api = {
  renderDiagnosticsPanel,
};

if (typeof globalThis !== "undefined") {
  globalThis.OdysseusDiagnostics = api;
}

export { renderDiagnosticsPanel };
