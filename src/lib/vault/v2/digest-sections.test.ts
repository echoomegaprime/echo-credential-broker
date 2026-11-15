// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MemoryEntryStore } from "./cards.ts";
import { ledgerAnchorSection, rotationDueSection } from "./digest-sections.ts";
import { MemoryAnchorStore } from "./ledger-anchor.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";

const WINDOW = { from: "2026-11-13T00:00:00.000Z", to: "2026-11-14T00:00:00.000Z" } as never;

describe("digest plug-in sections", () => {
  it("rotation: nothing due on an empty store", async () => {
    const section = await rotationDueSection({ entries: new MemoryEntryStore() }, () => Date.parse("2026-11-14T00:00:00Z"))(WINDOW, {});
    assert.equal(section.title, "ROTATION DUE");
    assert.deepEqual(section.lines, ["Nothing due."]);
  });

  it("anchor: a never-anchored ledger is flagged", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    const section = await ledgerAnchorSection({ ledger, anchors: new MemoryAnchorStore() })(WINDOW, {});
    assert.equal(section.title, "LEDGER ANCHOR");
    assert.match(section.lines[0], /^! Never anchored/);
  });
});
