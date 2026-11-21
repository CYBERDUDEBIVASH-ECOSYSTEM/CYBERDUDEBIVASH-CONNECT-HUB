#!/usr/bin/env node
// Owner directive 2026-11-20 (security-researcher findings #6-#13): no first-party page may link to, or declare in
// structured data, the Facebook, Instagram, X/Twitter, Tumblr or ORCID profiles or the GitHub profile page.
// GitHub repository links (github.com/<owner>/<repo>) and other organisations' pages remain allowed.
// Usage: node scripts/verify-no-retired-social-profiles.mjs [dir ...]   (default: src public functions dist)
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const RETIRED_PROFILE_LINKS = [
  ["x_handle", /https?:\/\/(?:www\.)?(?:x\.com|twitter\.com)\/(?:CDBSENTINELAPEX|cyberdudebivash|cyberbivash|Iambivash007)(?![A-Za-z0-9_])/i],
  ["facebook_profile", /https?:\/\/(?:(?:www|m|web|mobile)\.)?facebook\.com\/(?:profile\.php\b|cyberdudebivash|cyberbivash)/i],
  ["instagram_profile", /https?:\/\/(?:www\.)?instagram\.com\/(?:cyberdudebivash|cyberbivash)[A-Za-z0-9_.]*/i],
  ["github_profile", /https?:\/\/(?:www\.)?github\.com\/cyberdudebivash\/?(?![A-Za-z0-9_./-])/i],
  ["orcid_profile", /https?:\/\/(?:www\.)?orcid\.org\/\d{4}-/i],
  ["tumblr_profile", /https?:\/\/(?:cyberdudebivash|cyberbivash)[a-z0-9-]*\.tumblr\.com/i],
];
const TEXT = /\.(?:astro|html|js|mjs|ts|tsx|json|xml|txt|md|mdx|svg|css)$/i;

export function scan(root) {
  const found = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) { if (name !== "node_modules") walk(full); continue; }
      if (!TEXT.test(name)) continue;
      const body = readFileSync(full, "utf8");
      for (const [code, pattern] of RETIRED_PROFILE_LINKS) if (pattern.test(body)) found.push(`${relative(root, full)} (${code})`);
    }
  };
  if (existsSync(root)) walk(root);
  return found;
}

const direct = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (direct) {
  const base = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const dirs = process.argv.length > 2 ? process.argv.slice(2).map((d) => resolve(d)) : ["src", "public", "functions", "dist"].map((d) => join(base, d));
  const offenders = dirs.flatMap((d) => scan(d).map((f) => `${relative(base, d) || "."}/${f}`));
  if (offenders.length) {
    console.error("retired social-profile links found:\n  - " + offenders.join("\n  - "));
    process.exit(1);
  }
  console.log(`verify-no-retired-social-profiles: clean (${dirs.map((d) => relative(base, d) || ".").join(", ")})`);
}
