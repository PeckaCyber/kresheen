import { afterEach, beforeEach } from "vitest";
import { setAvailableMethodologies, type MethodologyInfo } from "./methodology";

/** A stand-in for a plugin's methodology: the core frontend knows nothing about which ones exist. */
export const DEMO_METHODOLOGY: MethodologyInfo = {
  name: "Demo",
  description: "A demo methodology.",
  categories: ["Alpha", "Beta", "Gamma"],
  category_descriptions: { Alpha: "The first demo category." },
};

/** Offers `Demo` (as `GET /api/capabilities` would) for the tests of the calling file, and resets afterwards. */
export function offerDemoMethodology(): void {
  beforeEach(() => setAvailableMethodologies([DEMO_METHODOLOGY]));
  afterEach(() => setAvailableMethodologies(null));
}
