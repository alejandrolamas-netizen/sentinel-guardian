/**
 * Sentinel Threat Intelligence - Integrity Test
 * Validates severity uint8 → string mapping.
 */

function severityLabel(s: number): string {
  if (s === 4) return "CRITICAL";
  if (s === 3) return "HIGH";
  if (s === 2) return "MEDIUM";
  if (s === 1) return "LOW";
  return "INFO";
}

describe("Sentinel Logic Tests", () => {
  test("Should identify CRITICAL (4) threats", () => {
    expect(severityLabel(4)).toBe("CRITICAL");
  });

  test("Should assign INFO to undefined values", () => {
    expect(severityLabel(0)).toBe("INFO");
  });
});
