import { test } from "node:test";
import assert from "node:assert/strict";
import { load } from "js-yaml";

// Small bounded regression for GHSA-2883-xcg3-v3hh. No stress/production input.
test("empty YAML merge sources consume the configured merge budget", () => {
  const source = "arr: &arr [" + Array(20).fill("{}").join(",") + "]\ntargets:\n"
    + "  - <<: *arr\n".repeat(20);
  assert.throws(() => load(source, { maxTotalMergeKeys: 100 }), /merge|limit/i);
});
