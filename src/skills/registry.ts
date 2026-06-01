/**
 * Skills Registry
 *
 * Install skills from remote sources:
 * - Git repos: git clone <url> ~/.automaton/skills/<name>
 * - URLs: fetch a SKILL.md from any URL
 * - Self-created: the automaton writes its own SKILL.md files
 */

import fs from "fs";
import path from "path";
import { URL } from "url";
import net from "net";
import type {
  Skill,
  SkillSource,
  AutomatonDatabase,
  ConwayClient,
} from "../types.js";
import { parseSkillMd } from "./format.js";

/**
 * Validate that a URL is safe to fetch:
 * - Must be https://
 * - Must point to a public host (not localhost, not a private IP)
 * Returns the parsed URL on success, or null on failure.
 */
function validateFetchUrl(url: string): URL | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  // Only allow https
  if (parsed.protocol !== "https:") {
    return null;
  }

  // Block private/reserved IP ranges
  const host = parsed.hostname;
  if (net.isIP(host)) {
    if (isPrivateIP(host)) {
      return null;
    }
  } else {
    // Hostname — reject if it resolves to a private IP
    // We check well-known local hostnames directly
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      host === "0.0.0.0" ||
      host.endsWith(".local") ||
      host.endsWith(".localhost")
    ) {
      return null;
    }
  }

  return parsed;
}

/**
 * Check if an IP address is in a private/reserved range.
 */
function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    // 127.0.0.0/8 (loopback)
    if (parts[0] === 127) return true;
    // 10.0.0.0/8 (private)
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 (private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 (private)
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 (link-local)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0/8
    if (parts[0] === 0) return true;
    // 100.64.0.0/10 (CGNAT)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    // 198.18.0.0/15 (benchmarking)
    if (parts[0] === 198 && parts[1] >= 18 && parts[1] <= 19) return true;
    return false;
  } else {
    // IPv6 — basic private ranges
    const lower = ip.toLowerCase();
    if (lower === "::1") return true;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // Unique local
    if (lower.startsWith("fe80")) return true; // Link-local
    return false;
  }
}

/**
 * Install a skill from a git repository.
 * Clones the repo into ~/.automaton/skills/<name>/
 */
export async function installSkillFromGit(
  repoUrl: string,
  name: string,
  skillsDir: string,
  db: AutomatonDatabase,
  conway: ConwayClient,
): Promise<Skill | null> {
  const resolvedDir = resolveHome(skillsDir);
  const targetDir = path.join(resolvedDir, name);

  // Clone via sandbox exec
  const result = await conway.exec(
    `git clone --depth 1 ${repoUrl} ${targetDir}`,
    60000,
  );

  if (result.exitCode !== 0) {
    throw new Error(`Failed to clone skill repo: ${result.stderr}`);
  }

  // Look for SKILL.md
  const skillMdPath = path.join(targetDir, "SKILL.md");
  const checkResult = await conway.exec(`cat ${skillMdPath}`, 5000);

  if (checkResult.exitCode !== 0) {
    throw new Error(`No SKILL.md found in cloned repo at ${skillMdPath}`);
  }

  const skill = parseSkillMd(checkResult.stdout, skillMdPath, "git");
  if (!skill) {
    throw new Error("Failed to parse SKILL.md from cloned repo");
  }

  db.upsertSkill(skill);
  return skill;
}

/**
 * Install a skill from a URL (fetches a single SKILL.md).
 */
export async function installSkillFromUrl(
  url: string,
  name: string,
  skillsDir: string,
  db: AutomatonDatabase,
  conway: ConwayClient,
): Promise<Skill | null> {
  const resolvedDir = resolveHome(skillsDir);
  const targetDir = path.join(resolvedDir, name);

  // Validate URL — must be https, not a private/internal IP
  const parsedUrl = validateFetchUrl(url);
  if (!parsedUrl) {
    throw new Error(
      `Invalid URL: must be an https:// URL pointing to a public host`,
    );
  }

  // Create directory (quote targetDir)
  await conway.exec(`mkdir -p "${targetDir}"`, 5000);

  // Fetch SKILL.md (quote both url and targetDir)
  const result = await conway.exec(
    `curl -fsSL "${url}" -o "${targetDir}/SKILL.md"`,
    30000,
  );

  if (result.exitCode !== 0) {
    throw new Error(`Failed to fetch SKILL.md from URL: ${result.stderr}`);
  }

  const content = await conway.exec(
    `cat "${targetDir}/SKILL.md"`,
    5000,
  );

  const skillMdPath = path.join(targetDir, "SKILL.md");
  const skill = parseSkillMd(content.stdout, skillMdPath, "url");
  if (!skill) {
    throw new Error("Failed to parse fetched SKILL.md");
  }

  db.upsertSkill(skill);
  return skill;
}

/**
 * Create a new skill authored by the automaton itself.
 */
export async function createSkill(
  name: string,
  description: string,
  instructions: string,
  skillsDir: string,
  db: AutomatonDatabase,
  conway: ConwayClient,
): Promise<Skill> {
  const resolvedDir = resolveHome(skillsDir);
  const targetDir = path.join(resolvedDir, name);

  // Create directory
  await conway.exec(`mkdir -p ${targetDir}`, 5000);

  // Write SKILL.md
  const content = `---
name: ${name}
description: "${description}"
auto-activate: true
---
${instructions}`;

  const skillMdPath = path.join(targetDir, "SKILL.md");
  await conway.writeFile(skillMdPath, content);

  const skill: Skill = {
    name,
    description,
    autoActivate: true,
    instructions,
    source: "self",
    path: skillMdPath,
    enabled: true,
    installedAt: new Date().toISOString(),
  };

  db.upsertSkill(skill);
  return skill;
}

/**
 * Remove a skill (disable in DB and optionally delete from disk).
 */
export async function removeSkill(
  name: string,
  db: AutomatonDatabase,
  conway: ConwayClient,
  skillsDir: string,
  deleteFiles: boolean = false,
): Promise<void> {
  db.removeSkill(name);

  if (deleteFiles) {
    const resolvedDir = resolveHome(skillsDir);
    const targetDir = path.join(resolvedDir, name);
    await conway.exec(`rm -rf ${targetDir}`, 5000);
  }
}

/**
 * List all installed skills.
 */
export function listSkills(db: AutomatonDatabase): Skill[] {
  return db.getSkills();
}

function resolveHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(process.env.HOME || "/root", p.slice(1));
  }
  return p;
}
