import type { MCPConnection } from '~/mcp/connection';
import type * as t from '~/mcp/types';
import { MCPServerInspector } from '~/mcp/registry/MCPServerInspector';
import { detectOAuthRequirement } from '~/mcp/oauth';
import { MCPConnectionFactory } from '~/mcp/MCPConnectionFactory';
import { createMockConnection } from './mcpConnectionsMock.helper';

// Mock external dependencies
jest.mock('../../oauth/detectOAuth');
jest.mock('../../MCPConnectionFactory');

const mockDetectOAuthRequirement = detectOAuthRequirement as jest.MockedFunction<
  typeof detectOAuthRequirement
>;

describe('MCPServerInspector', () => {
  let mockConnection: jest.Mocked<MCPConnection>;

  beforeEach(() => {
    mockConnection = createMockConnection('test_server');
    jest.clearAllMocks();
  });

  describe('inspect()', () => {
    it('should process env and fetch all metadata for non-OAuth stdio server with serverInstructions=true', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: true,
      };

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: false,
        method: 'no-metadata-found',
      });

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: 'instructions for test_server',
        requiresOAuth: false,
        capabilities:
          '{"tools":{"listChanged":true},"resources":{"listChanged":true},"prompts":{"get":"getPrompts for test_server"}}',
        tools: 'listFiles',
        toolFunctions: {
          listFiles_mcp_test_server: expect.objectContaining({
            type: 'function',
            function: expect.objectContaining({
              name: 'listFiles_mcp_test_server',
            }),
          }),
        },
        initDuration: expect.any(Number),
      });
    });

    it('should detect OAuth and skip capabilities fetch for streamable-http server', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'streamable-http',
        url: 'https://api.example.com/mcp',
      };

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: true,
        method: 'protected-resource-metadata',
      });

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'streamable-http',
        url: 'https://api.example.com/mcp',
        requiresOAuth: true,
        oauthMetadata: undefined,
        initDuration: expect.any(Number),
      });
    });

    it('should skip capabilities fetch when startup=false', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        startup: false,
      };

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        startup: false,
        requiresOAuth: false,
        initDuration: expect.any(Number),
      });
    });

    it('should keep custom serverInstructions string and not fetch from server', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: 'Custom instructions here',
      };

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: false,
        method: 'no-metadata-found',
      });

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: 'Custom instructions here',
        requiresOAuth: false,
        capabilities:
          '{"tools":{"listChanged":true},"resources":{"listChanged":true},"prompts":{"get":"getPrompts for test_server"}}',
        tools: 'listFiles',
        toolFunctions: expect.any(Object),
        initDuration: expect.any(Number),
      });
    });

    it('should handle serverInstructions as string "true" and fetch from server', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: 'true', // String "true" from YAML
      };

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: false,
        method: 'no-metadata-found',
      });

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: 'instructions for test_server',
        requiresOAuth: false,
        capabilities:
          '{"tools":{"listChanged":true},"resources":{"listChanged":true},"prompts":{"get":"getPrompts for test_server"}}',
        tools: 'listFiles',
        toolFunctions: expect.any(Object),
        initDuration: expect.any(Number),
      });
    });

    it('should handle predefined requiresOAuth without detection', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'sse',
        url: 'https://api.example.com/sse',
        requiresOAuth: true,
      };

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'sse',
        url: 'https://api.example.com/sse',
        requiresOAuth: true,
        initDuration: expect.any(Number),
      });
    });

    it('should fetch capabilities when server has no tools', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
      };

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: false,
        method: 'no-metadata-found',
      });

      // Mock server with no tools
      mockConnection.client.listTools = jest.fn().mockResolvedValue({ tools: [] });

      const result = await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      expect(result).toEqual({
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        requiresOAuth: false,
        capabilities:
          '{"tools":{"listChanged":true},"resources":{"listChanged":true},"prompts":{"get":"getPrompts for test_server"}}',
        tools: '',
        toolFunctions: {},
        initDuration: expect.any(Number),
      });
    });

    it('should create temporary connection when no connection is provided', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: true,
      };

      const tempMockConnection = createMockConnection('test_server');
      (MCPConnectionFactory.create as jest.Mock).mockResolvedValue(tempMockConnection);

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: false,
        method: 'no-metadata-found',
      });

      const result = await MCPServerInspector.inspect('test_server', rawConfig);

      // Verify factory was called to create connection
      expect(MCPConnectionFactory.create).toHaveBeenCalledWith({
        serverName: 'test_server',
        serverConfig: expect.objectContaining({ type: 'stdio', command: 'node' }),
      });

      // Verify temporary connection was disconnected
      expect(tempMockConnection.disconnect).toHaveBeenCalled();

      // Verify result is correct
      expect(result).toEqual({
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: 'instructions for test_server',
        requiresOAuth: false,
        capabilities:
          '{"tools":{"listChanged":true},"resources":{"listChanged":true},"prompts":{"get":"getPrompts for test_server"}}',
        tools: 'listFiles',
        toolFunctions: expect.any(Object),
        initDuration: expect.any(Number),
      });
    });

    it('should not create temporary connection when connection is provided', async () => {
      const rawConfig: t.MCPOptions = {
        type: 'stdio',
        command: 'node',
        args: ['server.js'],
        serverInstructions: true,
      };

      mockDetectOAuthRequirement.mockResolvedValue({
        requiresOAuth: false,
        method: 'no-metadata-found',
      });

      await MCPServerInspector.inspect('test_server', rawConfig, mockConnection);

      // Verify factory was NOT called
      expect(MCPConnectionFactory.create).not.toHaveBeenCalled();

      // Verify provided connection was NOT disconnected
      expect(mockConnection.disconnect).not.toHaveBeenCalled();
    });
  });

  describe('getToolFunctions()', () => {
    it('should convert MCP tools to LibreChat tool functions format', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'file_read',
            description: 'Read a file',
            inputSchema: {
              type: 'object',
              properties: { path: { type: 'string' } },
            },
          },
          {
            name: 'file_write',
            description: 'Write a file',
            inputSchema: {
              type: 'object',
              properties: {
                path: { type: 'string' },
                content: { type: 'string' },
              },
            },
          },
        ],
      });

      const result = await MCPServerInspector.getToolFunctions('my_server', mockConnection);

      expect(result).toEqual({
        file_read_mcp_my_server: {
          type: 'function',
          function: {
            name: 'file_read_mcp_my_server',
            description: 'Read a file',
            parameters: {
              type: 'object',
              properties: { path: { type: 'string' } },
            },
          },
        },
        file_write_mcp_my_server: {
          type: 'function',
          function: {
            name: 'file_write_mcp_my_server',
            description: 'Write a file',
            parameters: {
              type: 'object',
              properties: {
                path: { type: 'string' },
                content: { type: 'string' },
              },
            },
          },
        },
      });
    });

    it('should handle empty tools list', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({ tools: [] });

      const result = await MCPServerInspector.getToolFunctions('my_server', mockConnection);

      expect(result).toEqual({});
    });

    it('should filter tools using include pattern', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'file_read',
            description: 'Read a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_write',
            description: 'Write a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_delete',
            description: 'Delete a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
        ],
      });

      const toolFilter = {
        include: ['^file_read$', '^file_write$'],
      };

      const result = await MCPServerInspector.getToolFunctions(
        'my_server',
        mockConnection,
        toolFilter,
      );

      expect(result).toEqual({
        file_read_mcp_my_server: expect.objectContaining({
          type: 'function',
          function: expect.objectContaining({ name: 'file_read_mcp_my_server' }),
        }),
        file_write_mcp_my_server: expect.objectContaining({
          type: 'function',
          function: expect.objectContaining({ name: 'file_write_mcp_my_server' }),
        }),
      });
      expect(result['file_delete_mcp_my_server']).toBeUndefined();
    });

    it('should filter tools using exclude pattern', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'file_read',
            description: 'Read a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_write',
            description: 'Write a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_delete',
            description: 'Delete a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
        ],
      });

      const toolFilter = {
        exclude: ['.*delete.*', '.*write.*'],
      };

      const result = await MCPServerInspector.getToolFunctions(
        'my_server',
        mockConnection,
        toolFilter,
      );

      expect(result).toEqual({
        file_read_mcp_my_server: expect.objectContaining({
          type: 'function',
          function: expect.objectContaining({ name: 'file_read_mcp_my_server' }),
        }),
      });
      expect(result['file_write_mcp_my_server']).toBeUndefined();
      expect(result['file_delete_mcp_my_server']).toBeUndefined();
    });

    it('should apply include filter first, then exclude filter', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'file_read',
            description: 'Read a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_write',
            description: 'Write a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_delete',
            description: 'Delete a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'database_read',
            description: 'Read from database',
            inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
          },
        ],
      });

      const toolFilter = {
        include: ['^file_.*'], // Include all file operations
        exclude: ['.*delete.*'], // But exclude delete operations
      };

      const result = await MCPServerInspector.getToolFunctions(
        'my_server',
        mockConnection,
        toolFilter,
      );

      expect(result).toEqual({
        file_read_mcp_my_server: expect.objectContaining({
          type: 'function',
          function: expect.objectContaining({ name: 'file_read_mcp_my_server' }),
        }),
        file_write_mcp_my_server: expect.objectContaining({
          type: 'function',
          function: expect.objectContaining({ name: 'file_write_mcp_my_server' }),
        }),
      });
      // file_delete should be excluded
      expect(result['file_delete_mcp_my_server']).toBeUndefined();
      // database_read should not be included (doesn't match include pattern)
      expect(result['database_read_mcp_my_server']).toBeUndefined();
    });

    it('should return all tools when no filter is specified', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'file_read',
            description: 'Read a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
          {
            name: 'file_write',
            description: 'Write a file',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
          },
        ],
      });

      const result = await MCPServerInspector.getToolFunctions('my_server', mockConnection);

      expect(result).toEqual({
        file_read_mcp_my_server: expect.objectContaining({
          type: 'function',
        }),
        file_write_mcp_my_server: expect.objectContaining({
          type: 'function',
        }),
      });
    });

    it('should handle regex patterns with special characters', async () => {
      mockConnection.client.listTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'tool.read',
            description: 'Read tool',
            inputSchema: { type: 'object', properties: {} },
          },
          {
            name: 'tool_write',
            description: 'Write tool',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      });

      const toolFilter = {
        include: ['^tool\\..*'], // Escape the dot to match literal '.'
      };

      const result = await MCPServerInspector.getToolFunctions(
        'my_server',
        mockConnection,
        toolFilter,
      );

      expect(result).toEqual({
        'tool.read_mcp_my_server': expect.objectContaining({
          type: 'function',
        }),
      });
      expect(result['tool_write_mcp_my_server']).toBeUndefined();
    });

    describe('Issue-specific test cases: filter by tool name only, not server name', () => {
      it('should filter tools with prefix patterns (e.g., "generate_.*", "optimize_.*")', async () => {
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'generate_spl',
              description: 'Generate SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'optimize_spl',
              description: 'Optimize SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'explain_spl',
              description: 'Explain SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'run_splunk_query',
              description: 'Run Splunk query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'delete_index',
              description: 'Delete an index',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        const toolFilter = {
          include: ['generate_.*', 'optimize_.*', 'explain_.*', 'run_.*'],
        };

        const result = await MCPServerInspector.getToolFunctions(
          'splunk',
          mockConnection,
          toolFilter,
        );

        // Should include tools matching the prefixes
        expect(result['generate_spl_mcp_splunk']).toBeDefined();
        expect(result['optimize_spl_mcp_splunk']).toBeDefined();
        expect(result['explain_spl_mcp_splunk']).toBeDefined();
        expect(result['run_splunk_query_mcp_splunk']).toBeDefined();

        // Should exclude tools not matching any prefix
        expect(result['delete_index_mcp_splunk']).toBeUndefined();
      });

      it('should filter tools with suffix patterns (e.g., ".*_query", ".*_search")', async () => {
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'run_kubernetes_query',
              description: 'Run Kubernetes query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'execute_search',
              description: 'Execute search',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'get_pods',
              description: 'Get pods',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'run_splunk_query',
              description: 'Run Splunk query',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        const toolFilter = {
          include: ['.*_query$', '.*_search$'],
        };

        const result = await MCPServerInspector.getToolFunctions(
          'kubernetes',
          mockConnection,
          toolFilter,
        );

        // Should include tools ending with _query or _search
        expect(result['run_kubernetes_query_mcp_kubernetes']).toBeDefined();
        expect(result['execute_search_mcp_kubernetes']).toBeDefined();
        expect(result['run_splunk_query_mcp_kubernetes']).toBeDefined();

        // Should exclude tools not matching the suffix
        expect(result['get_pods_mcp_kubernetes']).toBeUndefined();
      });

      it('should filter tools with exact name matching', async () => {
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'generate_spl',
              description: 'Generate SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'optimize_spl',
              description: 'Optimize SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'explain_spl',
              description: 'Explain SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'run_splunk_query',
              description: 'Run Splunk query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'delete_index',
              description: 'Delete index',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        const toolFilter = {
          include: ['^generate_spl$', '^optimize_spl$', '^explain_spl$', '^run_splunk_query$'],
        };

        const result = await MCPServerInspector.getToolFunctions(
          'splunk',
          mockConnection,
          toolFilter,
        );

        // Should include only exact matches
        expect(result['generate_spl_mcp_splunk']).toBeDefined();
        expect(result['optimize_spl_mcp_splunk']).toBeDefined();
        expect(result['explain_spl_mcp_splunk']).toBeDefined();
        expect(result['run_splunk_query_mcp_splunk']).toBeDefined();

        // Should exclude non-matches
        expect(result['delete_index_mcp_splunk']).toBeUndefined();
      });

      it('should exclude tools with namespace/category patterns (e.g., "splunk.*", "kubernetes.*")', async () => {
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'splunk_search',
              description: 'Splunk search',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'splunk_query',
              description: 'Splunk query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'sourcebot_analyze',
              description: 'Sourcebot analyze',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'kubernetes_get_pods',
              description: 'Get Kubernetes pods',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'safe_tool',
              description: 'Safe tool',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        const toolFilter = {
          exclude: ['^splunk.*', '^sourcebot.*', '^kubernetes.*'],
        };

        const result = await MCPServerInspector.getToolFunctions(
          'mixed_server',
          mockConnection,
          toolFilter,
        );

        // Should exclude all tools starting with excluded prefixes
        expect(result['splunk_search_mcp_mixed_server']).toBeUndefined();
        expect(result['splunk_query_mcp_mixed_server']).toBeUndefined();
        expect(result['sourcebot_analyze_mcp_mixed_server']).toBeUndefined();
        expect(result['kubernetes_get_pods_mcp_mixed_server']).toBeUndefined();

        // Should include tools that don't match exclude patterns
        expect(result['safe_tool_mcp_mixed_server']).toBeDefined();
      });

      it('should work correctly when multiple servers expose tools with same names', async () => {
        // This tests that filters operate on tool name only, regardless of server name
        const tools = [
          {
            name: 'read_file',
            description: 'Read a file',
            inputSchema: { type: 'object', properties: {} },
          },
          {
            name: 'write_file',
            description: 'Write a file',
            inputSchema: { type: 'object', properties: {} },
          },
        ];

        mockConnection.client.listTools = jest.fn().mockResolvedValue({ tools });

        const toolFilter = {
          include: ['^read_.*'],
        };

        // Test with first server
        const resultServer1 = await MCPServerInspector.getToolFunctions(
          'server1',
          mockConnection,
          toolFilter,
        );

        // Test with second server
        const resultServer2 = await MCPServerInspector.getToolFunctions(
          'server2',
          mockConnection,
          toolFilter,
        );

        // Both servers should have only read_file, not write_file
        expect(resultServer1['read_file_mcp_server1']).toBeDefined();
        expect(resultServer1['write_file_mcp_server1']).toBeUndefined();

        expect(resultServer2['read_file_mcp_server2']).toBeDefined();
        expect(resultServer2['write_file_mcp_server2']).toBeUndefined();
      });

      it('should handle tools without extra server part in name', async () => {
        // Test tools that don't have server name as prefix/suffix
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'simple_tool',
              description: 'Simple tool',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'another_tool',
              description: 'Another tool',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        const toolFilter = {
          include: ['^simple_.*'],
        };

        const result = await MCPServerInspector.getToolFunctions(
          'any_server',
          mockConnection,
          toolFilter,
        );

        // Should filter based on tool name, not considering server name in filter
        expect(result['simple_tool_mcp_any_server']).toBeDefined();
        expect(result['another_tool_mcp_any_server']).toBeUndefined();
      });

      it('should support case-sensitive regex patterns', async () => {
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'ReadFile',
              description: 'Read file',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'readFile',
              description: 'Read file',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'READFILE',
              description: 'Read file',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        const toolFilter = {
          include: ['^read.*'], // Lowercase 'read' prefix
        };

        const result = await MCPServerInspector.getToolFunctions(
          'my_server',
          mockConnection,
          toolFilter,
        );

        // Should only match lowercase 'read'
        expect(result['readFile_mcp_my_server']).toBeDefined();
        expect(result['ReadFile_mcp_my_server']).toBeUndefined();
        expect(result['READFILE_mcp_my_server']).toBeUndefined();
      });

      it('should support plain strings (partial match) vs anchored patterns (exact match)', async () => {
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'generate_spl',
              description: 'Generate SPL',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'my_generate_spl',
              description: 'My generate SPL',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'generate_spl_query',
              description: 'Generate SPL query',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'other_tool',
              description: 'Other tool',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        // Test 1: Plain string matches any tool containing the pattern (partial match)
        const partialMatchFilter = {
          include: ['generate_spl'], // No anchors - matches any tool containing 'generate_spl'
        };

        const partialResult = await MCPServerInspector.getToolFunctions(
          'my_server',
          mockConnection,
          partialMatchFilter,
        );

        // Plain string matches all tools containing 'generate_spl'
        expect(partialResult['generate_spl_mcp_my_server']).toBeDefined();
        expect(partialResult['my_generate_spl_mcp_my_server']).toBeDefined();
        expect(partialResult['generate_spl_query_mcp_my_server']).toBeDefined();
        expect(partialResult['other_tool_mcp_my_server']).toBeUndefined();

        // Test 2: Anchored pattern matches exact tool name only
        const exactMatchFilter = {
          include: ['^generate_spl$'], // With anchors - exact match only
        };

        const exactResult = await MCPServerInspector.getToolFunctions(
          'my_server',
          mockConnection,
          exactMatchFilter,
        );

        // Anchored pattern matches only exact 'generate_spl'
        expect(exactResult['generate_spl_mcp_my_server']).toBeDefined();
        expect(exactResult['my_generate_spl_mcp_my_server']).toBeUndefined();
        expect(exactResult['generate_spl_query_mcp_my_server']).toBeUndefined();
        expect(exactResult['other_tool_mcp_my_server']).toBeUndefined();
      });

      it('should exclude tools from alertbot server (real user scenario)', async () => {
        // Real scenario from user: alertbot server with 9 tools
        mockConnection.client.listTools = jest.fn().mockResolvedValue({
          tools: [
            {
              name: 'prometheus_top_n_alerts',
              description: 'Get top N alerts',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'prometheus_list_entities',
              description: 'List entities',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'sourcebot_search_code',
              description: 'Search code',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'sourcebot_get_file_source',
              description: 'Get file source',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'splunk_get_workload_logs',
              description: 'Get workload logs',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'kubernetes_get_cluster_events',
              description: 'Get cluster events',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'kubernetes_get_runbook',
              description: 'Get runbook',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'kubernetes_get_resource',
              description: 'Get resource',
              inputSchema: { type: 'object', properties: {} },
            },
            {
              name: 'alertbot_guides',
              description: 'Get guides',
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        });

        // User's config: exclude splunk, sourcebot, and kubernetes tools
        const toolFilter = {
          exclude: ['splunk.*', 'sourcebot.*', 'kubernetes.*'],
        };

        const result = await MCPServerInspector.getToolFunctions(
          'alertbot',
          mockConnection,
          toolFilter,
        );

        // Only prometheus and alertbot tools should remain
        expect(result['prometheus_top_n_alerts_mcp_alertbot']).toBeDefined();
        expect(result['prometheus_list_entities_mcp_alertbot']).toBeDefined();
        expect(result['alertbot_guides_mcp_alertbot']).toBeDefined();

        // Splunk, sourcebot, and kubernetes tools should be excluded
        expect(result['sourcebot_search_code_mcp_alertbot']).toBeUndefined();
        expect(result['sourcebot_get_file_source_mcp_alertbot']).toBeUndefined();
        expect(result['splunk_get_workload_logs_mcp_alertbot']).toBeUndefined();
        expect(result['kubernetes_get_cluster_events_mcp_alertbot']).toBeUndefined();
        expect(result['kubernetes_get_runbook_mcp_alertbot']).toBeUndefined();
        expect(result['kubernetes_get_resource_mcp_alertbot']).toBeUndefined();
      });
    });
  });
});
