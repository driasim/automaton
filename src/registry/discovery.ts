/**
 * Agent Discovery
 *
 * Discover other agents via ERC-8004 registry queries.
 * Fetch and parse agent cards from URIs.
 */

import { URL } from "url";
import net from "net";
import type {
  DiscoveredAgent,
  AgentCard,
} from "../types.js";
import { queryAgent, getTotalAgents } from "./erc8004.js";

type Network = "mainnet" | "testnet";

/**
 * Discover agents by scanning the registry.
 * Returns a list of discovered agents with their metadata.
 */
export async function discoverAgents(
  limit: number = 20,
  network: Network = "mainnet",
): Promise<DiscoveredAgent[]> {
  const total = await getTotalAgents(network);
  const scanCount = Math.min(total, limit);
  const agents: DiscoveredAgent[] = [];

  // Scan from most recent to oldest
  for (let i = total; i > total - scanCount && i > 0; i--) {
    const agent = await queryAgent(i.toString(), network);
    if (agent) {
      // Try to fetch the agent card for additional metadata
      try {
        const card = await fetchAgentCard(agent.agentURI);
        if (card) {
          agent.name = card.name;
          agent.description = card.description;
        }
      } catch {
        // Card fetch failed, use basic info
      }
      agents.push(agent);
    }
  }

  return agents;
}

/**
 * Validate that a URI is safe to fetch.
 * Only https:// and ipfs:// (converted to https://ipfs.io/) are allowed.
 * Private/reserved IPs are blocked.
 */
function validateAgentCardUri(uri: string): string | null {
  // Handle IPFS URIs — convert to https gateway
  if (uri.startsWith("ipfs://")) {
    return `https://ipfs.io/ipfs/${uri.slice(7)}`;
  }

  // Must be https at this point
  if (!uri.startsWith("https://")) {
    return null;
  }

  // Validate the URL structure and block private IPs
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:") return null;

    const host = parsed.hostname;

    // Block private/reserved IPs
    if (net.isIP(host) && isPrivateIP(host)) {
      return null;
    }

    // Block known local hostnames
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

    return uri;
  } catch {
    return null;
  }
}

/**
 * Check if an IP address is in a private/reserved range.
 */
function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 127) return true;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] === 198 && parts[1] >= 18 && parts[1] <= 19) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === "::1") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (lower.startsWith("fe80")) return true;
  return false;
}

/**
 * Fetch an agent card from a URI.
 */
export async function fetchAgentCard(
  uri: string,
): Promise<AgentCard | null> {
  try {
    // Validate and resolve the URI
    const fetchUrl = validateAgentCardUri(uri);
    if (!fetchUrl) {
      return null;
    }

    const response = await fetch(fetchUrl, {
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) return null;

    const card = (await response.json()) as AgentCard;

    // Basic validation
    if (!card.name || !card.type) return null;

    return card;
  } catch {
    return null;
  }
}

/**
 * Search for agents by name or description.
 * Scans recent registrations and filters by keyword.
 */
export async function searchAgents(
  keyword: string,
  limit: number = 10,
  network: Network = "mainnet",
): Promise<DiscoveredAgent[]> {
  const all = await discoverAgents(50, network);
  const lower = keyword.toLowerCase();

  return all
    .filter(
      (a) =>
        a.name?.toLowerCase().includes(lower) ||
        a.description?.toLowerCase().includes(lower) ||
        a.owner.toLowerCase().includes(lower),
    )
    .slice(0, limit);
}
