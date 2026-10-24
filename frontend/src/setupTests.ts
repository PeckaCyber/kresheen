import "@testing-library/jest-dom/vitest";
import { configure } from "@testing-library/react";

// findBy* and waitFor give up after 1 s by default, which a slow CI runner can miss (a render took 1.06 s on
// 2026-10-24). 3 s stays under Vitest's 5 s test timeout, so a real failure still reports as a missing element.
configure({ asyncUtilTimeout: 3000 });

// jsdom has no matchMedia; react-bootstrap's Offcanvas asks for it on render.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
