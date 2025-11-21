import { Constants } from 'librechat-data-provider';
import { logger } from '@librechat/data-schemas';
import type { JsonSchemaType } from '@librechat/data-schemas';
import type { MCPConnection } from '~/mcp/connection';
import type * as t from '~/mcp/types';
import { detectOAuthRequirement } from '~/mcp/oauth';
import { isEnabled } from '~/utils';
import { MCPConnectionFactory } from '~/mcp/MCPConnectionFactory';

/**
 * Inspects MCP servers to discover their metadata, capabilities, and tools.
 * Connects to servers and populates configuration with OAuth requirements,
 * server instructions, capabilities, and available tools.
 */
export class MCPServerInspector {
  private constructor(
    private readonly serverName: string,
    private readonly config: t.ParsedServerConfig,
    private connection: MCPConnection | undefined,
  ) {}

  /**
   * Inspects a server and returns an enriched configuration with metadata.
   * Detects OAuth requirements and fetches server capabilities.
   * @param serverName - The name of the server (used for tool function naming)
   * @param rawConfig - The raw server configuration
   * @param connection - The MCP connection
   * @returns A fully processed and enriched configuration with server metadata
   */
  public static async inspect(
    serverName: string,
    rawConfig: t.MCPOptions,
    connection?: MCPConnection,
  ): Promise<t.ParsedServerConfig> {
    const start = Date.now();
    logger.debug(`[MCP][${serverName}][Inspector] Starting inspection`, {
      hasToolFilter: !!rawConfig.toolFilter,
      toolFilter: rawConfig.toolFilter,
      startup: rawConfig.startup,
    });
    const inspector = new MCPServerInspector(serverName, rawConfig, connection);
    await inspector.inspectServer();
    inspector.config.initDuration = Date.now() - start;
    logger.debug(`[MCP][${serverName}][Inspector] Inspection complete`, {
      initDuration: inspector.config.initDuration,
      toolCount: inspector.config.toolFunctions
        ? Object.keys(inspector.config.toolFunctions).length
        : 0,
      hasToolFilter: !!inspector.config.toolFilter,
    });
    return inspector.config;
  }

  private async inspectServer(): Promise<void> {
    await this.detectOAuth();

    if (this.config.startup !== false && !this.config.requiresOAuth) {
      let tempConnection = false;
      if (!this.connection) {
        tempConnection = true;
        this.connection = await MCPConnectionFactory.create({
          serverName: this.serverName,
          serverConfig: this.config,
        });
      }

      await Promise.allSettled([
        this.fetchServerInstructions(),
        this.fetchServerCapabilities(),
        this.fetchToolFunctions(),
      ]);

      if (tempConnection) await this.connection.disconnect();
    }
  }

  private async detectOAuth(): Promise<void> {
    if (this.config.requiresOAuth != null) return;
    if (this.config.url == null || this.config.startup === false) {
      this.config.requiresOAuth = false;
      return;
    }

    const result = await detectOAuthRequirement(this.config.url);
    this.config.requiresOAuth = result.requiresOAuth;
    this.config.oauthMetadata = result.metadata;
  }

  private async fetchServerInstructions(): Promise<void> {
    if (isEnabled(this.config.serverInstructions)) {
      this.config.serverInstructions = this.connection!.client.getInstructions();
    }
  }

  private async fetchServerCapabilities(): Promise<void> {
    const capabilities = this.connection!.client.getServerCapabilities();
    this.config.capabilities = JSON.stringify(capabilities);
    const tools = await this.connection!.client.listTools();
    this.config.tools = tools.tools.map((tool) => tool.name).join(', ');
  }

  private async fetchToolFunctions(): Promise<void> {
    logger.debug(`[MCP][${this.serverName}][Inspector] Fetching tool functions`, {
      hasToolFilter: !!this.config.toolFilter,
      toolFilter: this.config.toolFilter,
    });
    this.config.toolFunctions = await MCPServerInspector.getToolFunctions(
      this.serverName,
      this.connection!,
      this.config.toolFilter,
    );
    logger.debug(
      `[MCP][${this.serverName}][Inspector] Tool functions fetched: ${Object.keys(this.config.toolFunctions).length} tools`,
    );
  }

  /**
   * Filters tool names based on include/exclude regex patterns
   * @param toolNames - Array of tool names to filter
   * @param toolFilter - Filter configuration with include/exclude patterns
   * @param serverName - Server name for logging
   * @returns Filtered array of tool names
   */
  private static filterTools(
    toolNames: string[],
    toolFilter: { include?: string[]; exclude?: string[] } | undefined,
    serverName: string,
  ): string[] {
    const logPrefix = `[MCP][${serverName}][ToolFilter]`;

    logger.debug(`${logPrefix} Starting filter`, {
      toolCount: toolNames.length,
      toolNames: toolNames,
      hasToolFilter: !!toolFilter,
      toolFilter: toolFilter,
    });

    if (!toolFilter) {
      logger.debug(
        `${logPrefix} No toolFilter configured, returning all ${toolNames.length} tools`,
      );
      return toolNames;
    }

    let filteredTools = [...toolNames];

    // Apply include filter first (whitelist)
    if (toolFilter.include && toolFilter.include.length > 0) {
      try {
        logger.debug(`${logPrefix} Applying include filter`, {
          patterns: toolFilter.include,
        });
        const includePatterns = toolFilter.include.map((pattern) => new RegExp(pattern));
        const beforeCount = filteredTools.length;
        filteredTools = filteredTools.filter((toolName) =>
          includePatterns.some((pattern) => pattern.test(toolName)),
        );
        const blocked = toolNames.filter((name) => !filteredTools.includes(name));
        if (blocked.length > 0) {
          logger.info(
            `${logPrefix} Include filter blocked ${blocked.length} tool(s): ${blocked.join(', ')}`,
          );
        }
        logger.info(
          `${logPrefix} Include filter: ${beforeCount} tools -> ${filteredTools.length} tools`,
        );
      } catch (error) {
        logger.error(`${logPrefix} Invalid include regex pattern:`, error);
      }
    }

    // Apply exclude filter (blacklist)
    if (toolFilter.exclude && toolFilter.exclude.length > 0) {
      try {
        logger.debug(`${logPrefix} Applying exclude filter`, {
          patterns: toolFilter.exclude,
        });
        const excludePatterns = toolFilter.exclude.map((pattern) => new RegExp(pattern));
        const beforeCount = filteredTools.length;
        const excluded = filteredTools.filter((toolName) =>
          excludePatterns.some((pattern) => pattern.test(toolName)),
        );
        filteredTools = filteredTools.filter(
          (toolName) => !excludePatterns.some((pattern) => pattern.test(toolName)),
        );
        if (excluded.length > 0) {
          logger.info(
            `${logPrefix} Exclude filter blocked ${excluded.length} tool(s): ${excluded.join(', ')}`,
          );
        }
        logger.info(
          `${logPrefix} Exclude filter: ${beforeCount} tools -> ${filteredTools.length} tools`,
        );
      } catch (error) {
        logger.error(`${logPrefix} Invalid exclude regex pattern:`, error);
      }
    }

    logger.debug(`${logPrefix} Filter complete`, {
      originalCount: toolNames.length,
      filteredCount: filteredTools.length,
      filteredTools: filteredTools,
    });

    return filteredTools;
  }

  /**
   * Converts server tools to LibreChat-compatible tool functions format.
   * @param serverName - The name of the server
   * @param connection - The MCP connection
   * @param toolFilter - Optional filter configuration for controlling which tools are exposed
   * @returns Tool functions formatted for LibreChat
   */
  public static async getToolFunctions(
    serverName: string,
    connection: MCPConnection,
    toolFilter?: { include?: string[]; exclude?: string[] },
  ): Promise<t.LCAvailableTools> {
    logger.debug(`[MCP][${serverName}][getToolFunctions] Starting`, {
      hasToolFilter: !!toolFilter,
      toolFilter: toolFilter,
    });

    const { tools }: t.MCPToolListResponse = await connection.client.listTools();
    logger.debug(
      `[MCP][${serverName}][getToolFunctions] Listed ${tools.length} tools from server`,
      {
        toolNames: tools.map((t) => t.name),
      },
    );

    // Filter tools based on toolFilter configuration
    const toolNames = tools.map((tool) => tool.name);
    const filteredToolNames = MCPServerInspector.filterTools(toolNames, toolFilter, serverName);

    logger.debug(
      `[MCP][${serverName}][getToolFunctions] After filtering: ${filteredToolNames.length} tools`,
      {
        filteredToolNames,
        originalCount: toolNames.length,
        filteredCount: filteredToolNames.length,
      },
    );

    const toolFunctions: t.LCAvailableTools = {};
    tools.forEach((tool) => {
      // Only include tools that passed the filter
      if (!filteredToolNames.includes(tool.name)) {
        logger.debug(
          `[MCP][${serverName}][getToolFunctions] Skipping filtered-out tool: ${tool.name}`,
        );
        return;
      }

      const name = `${tool.name}${Constants.mcp_delimiter}${serverName}`;
      toolFunctions[name] = {
        type: 'function',
        ['function']: {
          name,
          description: tool.description,
          parameters: tool.inputSchema as JsonSchemaType,
        },
      };
    });

    logger.debug(
      `[MCP][${serverName}][getToolFunctions] Created ${Object.keys(toolFunctions).length} tool functions`,
      {
        toolFunctionKeys: Object.keys(toolFunctions),
      },
    );

    return toolFunctions;
  }
}
