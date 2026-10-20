import { describe, expect, it } from "vitest";
import { extensions } from "./extensions";

describe("core build with no plugin frontend", () => {
  it("has every slot empty", () => {
    for (const slot of Object.values(extensions)) expect(slot).toEqual([]);
  });
});
