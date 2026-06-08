/* Review packet frontend safety wrapper. */
import { renderReviewPacket, preventEnterApproval } from "./toolSafety.js";

const api = {
  renderReviewPacket,
  preventEnterApproval,
};

if (typeof globalThis !== "undefined") {
  globalThis.OdysseusReviewPackets = api;
}

export { renderReviewPacket, preventEnterApproval };
