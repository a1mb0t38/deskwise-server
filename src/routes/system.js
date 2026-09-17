import express from "express";
import { readFile } from "fs/promises";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
// A03 — lodash is actually imported and used here so the dependency is real
import _ from "lodash";

const __dirname = dirname(fileURLToPath(import.meta.url));
const router = express.Router();

/**
 * GET /api/system/dependencies
 *
 * VULNERABILITY (A03 — Software Supply Chain Failures, CWE-1395):
 * This endpoint lists installed npm package versions. The app ships
 * lodash@4.17.4, which is affected by CVE-2019-10744 (prototype pollution
 * via the `merge`, `mergeWith`, `defaultsDeep` family of functions).
 *
 * The flag for this category is knowledge-based: a player reads the
 * package versions here, identifies the vulnerable package and its CVE,
 * then submits the flag string to POST /api/flags/submit:
 *   { "flag": "SUPPLYCHAIN{CVE-2019-10744}" }
 *
 * lodash is also actively used in the ticket search/import logic to make
 * the dependency genuine, not cosmetic.
 *
 * Exploit path:
 *   1. GET /api/system/dependencies — note lodash version
 *   2. Research CVE-2019-10744 (prototype pollution in lodash < 4.17.19)
 *   3. Submit SUPPLYCHAIN{CVE-2019-10744} to /api/flags/submit
 */
router.get("/dependencies", async (req, res) => {
  try {
    const pkgPath = resolve(__dirname, "../../package.json");
    const raw = await readFile(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);

    // Use lodash here so the dependency isn't tree-shaken (active usage)
    const deps = _.mapValues(pkg.dependencies || {}, (version) => ({ version }));
    const devDeps = _.mapValues(pkg.devDependencies || {}, (version) => ({
      version,
    }));

    return res.json({
      name: pkg.name,
      version: pkg.version,
      dependencies: deps,
      devDependencies: devDeps,
      note: "Review installed package versions for known vulnerabilities.",
      hint: "One of these packages has a well-known CVE. Can you find it?",
    });
  } catch (err) {
    console.error("Dependencies fetch error:", err);
    return res.status(500).json({ error: "Failed to read package info" });
  }
});

export default router;
