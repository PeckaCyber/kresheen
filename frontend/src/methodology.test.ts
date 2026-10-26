import { beforeEach, describe, expect, it } from "vitest";
import {
  categoryDescription,
  isMethodologyAvailable,
  methodologyCategories,
  methodologyDescription,
  selectableMethodologies,
  setAvailableMethodologies,
  threatMethodologies,
  threatMethodologiesWith,
} from "./methodology";
import { DEMO_METHODOLOGY } from "./testMethodologies";

describe("categoryDescription", () => {
  it("returns undefined for null or undefined category", () => {
    expect(categoryDescription("STRIDE", null)).toBeUndefined();
    expect(categoryDescription("STRIDE", undefined)).toBeUndefined();
  });

  it("returns description for STRIDE categories by camelCase key", () => {
    expect(categoryDescription("STRIDE", "Spoofing")).toBe("Someone pretends to be a user or service they are not.");
    expect(categoryDescription("STRIDE", "Tampering")).toBe("Data or code is modified without authorization.");
    expect(categoryDescription("STRIDE", "Repudiation")).toBe(
      "An attacker denies performing an action and cannot be proven otherwise.",
    );
    expect(categoryDescription("STRIDE", "InformationDisclosure")).toBe(
      "Data is disclosed to people who should not have access.",
    );
    expect(categoryDescription("STRIDE", "DenialOfService")).toBe(
      "An attacker makes a service unavailable or unusable.",
    );
    expect(categoryDescription("STRIDE", "ElevationOfPrivilege")).toBe(
      "An attacker gains higher-level permissions than intended.",
    );
  });

  it("returns a plugin methodology's descriptions once the server offers it", () => {
    setAvailableMethodologies([DEMO_METHODOLOGY]);
    try {
      expect(categoryDescription("Demo", "Alpha")).toBe("The first demo category.");
      expect(categoryDescription("Demo", "Beta")).toBeUndefined();
    } finally {
      setAvailableMethodologies(null);
    }
    expect(categoryDescription("Demo", "Alpha")).toBeUndefined();
  });

  it("returns undefined for Custom methodology", () => {
    expect(categoryDescription("Custom", "Any category")).toBeUndefined();
  });

  it("returns undefined for unknown methodology", () => {
    expect(categoryDescription("UnknownMethodology", "SomeCategory")).toBeUndefined();
  });
});

describe("the available methodologies", () => {
  beforeEach(() => setAvailableMethodologies(null));

  it("are STRIDE alone, plus Custom for authoring, until the server offers more", () => {
    expect(selectableMethodologies()).toEqual(["STRIDE"]);
    expect(threatMethodologies()).toEqual(["STRIDE", "Custom"]);
    expect(methodologyCategories("STRIDE")).toHaveLength(6);
    expect(methodologyCategories("Demo")).toEqual([]);
    expect(isMethodologyAvailable("Demo")).toBe(false);
    expect(isMethodologyAvailable("Custom")).toBe(true);
  });

  it("follow the server's list, with STRIDE always first and built in", () => {
    setAvailableMethodologies([{ ...DEMO_METHODOLOGY, name: "STRIDE", categories: ["x"] }, DEMO_METHODOLOGY]);
    expect(selectableMethodologies()).toEqual(["STRIDE", "Demo"]);
    expect(methodologyCategories("STRIDE")).toHaveLength(6); // not overridden by the server's entry
    expect(methodologyCategories("Demo")).toEqual(["Alpha", "Beta", "Gamma"]);
    expect(methodologyDescription("Demo")).toBe("A demo methodology.");
    expect(methodologyDescription("Custom")).toBe("A threat you described yourself.");
  });

  it("can list a name already in use that the server no longer offers", () => {
    expect(threatMethodologiesWith(["Demo", "STRIDE"])).toEqual(["STRIDE", "Custom", "Demo"]);
  });
});
