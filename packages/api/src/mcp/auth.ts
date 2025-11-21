import { logger } from '@librechat/data-schemas';
import { Constants } from 'librechat-data-provider';
import type { PluginAuthMethods } from '@librechat/data-schemas';
import type { GenericTool } from '@librechat/agents';
import { getPluginAuthMap } from '~/agents/auth';

export async function getUserMCPAuthMap({
  userId,
  tools,
  servers,
  toolInstances,
  findPluginAuthsByKeys,
}: {
  userId: string;
  tools?: (string | undefined)[];
  servers?: (string | undefined)[];
  toolInstances?: (GenericTool | null)[];
  findPluginAuthsByKeys: PluginAuthMethods['findPluginAuthsByKeys'];
}) {
  let allMcpCustomUserVars: Record<string, Record<string, string>> = {};
  let mcpPluginKeysToFetch: string[] = [];

  logger.debug('[MCP Auth] Starting getUserMCPAuthMap', {
    userId,
    hasTools: !!tools,
    toolsCount: tools?.length || 0,
    hasServers: !!servers,
    serversCount: servers?.length || 0,
    hasToolInstances: !!toolInstances,
    toolInstancesCount: toolInstances?.length || 0,
  });

  try {
    const uniqueMcpServers = new Set<string>();

    if (servers != null && servers.length) {
      logger.debug('[MCP Auth] Processing servers list', { count: servers.length });
      for (const serverName of servers) {
        if (!serverName) {
          continue;
        }
        const pluginKey = `${Constants.mcp_prefix}${serverName}`;
        uniqueMcpServers.add(pluginKey);
        logger.debug('[MCP Auth] Added server to lookup', { serverName, pluginKey });
      }
    } else if (tools != null && tools.length) {
      logger.debug('[MCP Auth] Processing tools list', { count: tools.length });
      for (const toolName of tools) {
        if (!toolName) {
          continue;
        }
        const delimiterIndex = toolName.indexOf(Constants.mcp_delimiter);
        if (delimiterIndex === -1) continue;
        const mcpServer = toolName.slice(delimiterIndex + Constants.mcp_delimiter.length);
        if (!mcpServer) continue;
        const pluginKey = `${Constants.mcp_prefix}${mcpServer}`;
        uniqueMcpServers.add(pluginKey);
        logger.debug('[MCP Auth] Extracted server from tool', { toolName, mcpServer, pluginKey });
      }
    } else if (toolInstances != null && toolInstances.length) {
      logger.debug('[MCP Auth] Processing tool instances', { count: toolInstances.length });
      for (const tool of toolInstances) {
        if (!tool) {
          continue;
        }
        const mcpTool = tool as GenericTool & { mcpRawServerName?: string };
        if (mcpTool.mcpRawServerName) {
          const pluginKey = `${Constants.mcp_prefix}${mcpTool.mcpRawServerName}`;
          uniqueMcpServers.add(pluginKey);
          logger.debug('[MCP Auth] Extracted server from tool instance', {
            serverName: mcpTool.mcpRawServerName,
            pluginKey,
          });
        }
      }
    }

    if (uniqueMcpServers.size === 0) {
      logger.debug('[MCP Auth] No MCP servers found to fetch auth for', { userId });
      return {};
    }

    mcpPluginKeysToFetch = Array.from(uniqueMcpServers);
    logger.debug('[MCP Auth] Fetching auth for MCP servers', {
      userId,
      pluginKeys: mcpPluginKeysToFetch,
      count: mcpPluginKeysToFetch.length,
    });

    allMcpCustomUserVars = await getPluginAuthMap({
      userId,
      pluginKeys: mcpPluginKeysToFetch,
      throwError: false,
      findPluginAuthsByKeys,
    });

    logger.debug('[MCP Auth] Auth lookup completed', {
      userId,
      resultKeys: Object.keys(allMcpCustomUserVars),
      resultCount: Object.keys(allMcpCustomUserVars).length,
    });
  } catch (err) {
    logger.error('[MCP Auth] Error fetching auth map', {
      userId,
      pluginKeys: mcpPluginKeysToFetch,
      error: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack : undefined,
    });
  }

  return allMcpCustomUserVars;
}
