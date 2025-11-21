import { logger } from '@librechat/data-schemas';
import type { OAuthTokens, OAuthClientInformation } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { TokenMethods, IToken } from '@librechat/data-schemas';
import type { MCPOAuthTokens, ExtendedOAuthTokens, OAuthMetadata } from './types';
import { encryptV2, decryptV2 } from '~/crypto';
import { isSystemUserId } from '~/mcp/enum';

interface StoreTokensParams {
  userId: string;
  serverName: string;
  tokens: OAuthTokens | ExtendedOAuthTokens | MCPOAuthTokens;
  createToken: TokenMethods['createToken'];
  updateToken?: TokenMethods['updateToken'];
  findToken?: TokenMethods['findToken'];
  clientInfo?: OAuthClientInformation;
  metadata?: OAuthMetadata;
  /** Optional: Pass existing token state to avoid duplicate DB calls */
  existingTokens?: {
    accessToken?: IToken | null;
    refreshToken?: IToken | null;
    clientInfoToken?: IToken | null;
  };
}

interface GetTokensParams {
  userId: string;
  serverName: string;
  findToken: TokenMethods['findToken'];
  refreshTokens?: (
    refreshToken: string,
    metadata: { userId: string; serverName: string; identifier: string },
  ) => Promise<MCPOAuthTokens>;
  createToken?: TokenMethods['createToken'];
  updateToken?: TokenMethods['updateToken'];
}

export class MCPTokenStorage {
  static getLogPrefix(userId: string, serverName: string): string {
    return isSystemUserId(userId)
      ? `[MCP][${serverName}]`
      : `[MCP][User: ${userId}][${serverName}]`;
  }

  /**
   * Stores OAuth tokens for an MCP server
   *
   * @param params.existingTokens - Optional: Pass existing token state to avoid duplicate DB calls.
   * This is useful when refreshing tokens, as getTokens() already has the token state.
   */
  static async storeTokens({
    userId,
    serverName,
    tokens,
    createToken,
    updateToken,
    findToken,
    clientInfo,
    existingTokens,
    metadata,
  }: StoreTokensParams): Promise<void> {
    const logPrefix = this.getLogPrefix(userId, serverName);

    logger.debug(`${logPrefix} Starting token storage`, {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      hasClientInfo: !!clientInfo,
      hasMetadata: !!metadata,
      existingTokensProvided: !!existingTokens,
    });

    try {
      const identifier = `mcp:${serverName}`;
      logger.debug(`${logPrefix} Using identifier: ${identifier}`);

      // Encrypt and store access token
      const encryptedAccessToken = await encryptV2(tokens.access_token);

      logger.debug(
        `${logPrefix} Token expires_in: ${'expires_in' in tokens ? tokens.expires_in : 'N/A'}, expires_at: ${'expires_at' in tokens ? tokens.expires_at : 'N/A'}`,
      );

      // Handle both expires_in and expires_at formats
      let accessTokenExpiry: Date;
      if ('expires_at' in tokens && tokens.expires_at) {
        /** MCPOAuthTokens format - already has calculated expiry */
        logger.debug(`${logPrefix} Using expires_at: ${tokens.expires_at}`);
        accessTokenExpiry = new Date(tokens.expires_at);
      } else if (tokens.expires_in) {
        /** Standard OAuthTokens format - calculate expiry */
        logger.debug(`${logPrefix} Using expires_in: ${tokens.expires_in}`);
        accessTokenExpiry = new Date(Date.now() + tokens.expires_in * 1000);
      } else {
        /** No expiry provided - default to 1 year */
        logger.debug(`${logPrefix} No expiry provided, using default`);
        accessTokenExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
      }

      logger.debug(`${logPrefix} Calculated expiry date: ${accessTokenExpiry.toISOString()}`);
      logger.debug(
        `${logPrefix} Date object: ${JSON.stringify({
          time: accessTokenExpiry.getTime(),
          valid: !isNaN(accessTokenExpiry.getTime()),
          iso: accessTokenExpiry.toISOString(),
        })}`,
      );

      // Ensure the date is valid before passing to createToken
      if (isNaN(accessTokenExpiry.getTime())) {
        logger.error(`${logPrefix} Invalid expiry date calculated, using default`);
        accessTokenExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
      }

      // Calculate expiresIn (seconds from now)
      const expiresIn = Math.floor((accessTokenExpiry.getTime() - Date.now()) / 1000);

      const accessTokenData = {
        userId,
        type: 'mcp_oauth',
        identifier,
        token: encryptedAccessToken,
        expiresIn: expiresIn > 0 ? expiresIn : 365 * 24 * 60 * 60, // Default to 1 year if negative
      };

      // Check if token already exists and update if it does
      if (findToken && updateToken) {
        // Use provided existing token state if available, otherwise look it up
        const existingToken =
          existingTokens?.accessToken !== undefined
            ? existingTokens.accessToken
            : await findToken({ userId, identifier });

        if (existingToken) {
          await updateToken({ userId, identifier }, accessTokenData);
          logger.debug(`${logPrefix} Updated existing access token`);
        } else {
          await createToken(accessTokenData);
          logger.debug(`${logPrefix} Created new access token`);
        }
      } else {
        // Create new token if it's initial store or update methods not provided
        await createToken(accessTokenData);
        logger.debug(`${logPrefix} Created access token (no update methods available)`);
      }

      // Store refresh token if available
      if (tokens.refresh_token) {
        const encryptedRefreshToken = await encryptV2(tokens.refresh_token);
        const extendedTokens = tokens as ExtendedOAuthTokens;
        const refreshTokenExpiry = extendedTokens.refresh_token_expires_in
          ? new Date(Date.now() + extendedTokens.refresh_token_expires_in * 1000)
          : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // Default to 1 year

        /** Calculated expiresIn for refresh token */
        const refreshExpiresIn = Math.floor((refreshTokenExpiry.getTime() - Date.now()) / 1000);

        const refreshTokenData = {
          userId,
          type: 'mcp_oauth_refresh',
          identifier: `${identifier}:refresh`,
          token: encryptedRefreshToken,
          expiresIn: refreshExpiresIn > 0 ? refreshExpiresIn : 365 * 24 * 60 * 60,
        };

        // Check if refresh token already exists and update if it does
        if (findToken && updateToken) {
          // Use provided existing token state if available, otherwise look it up
          const existingRefreshToken =
            existingTokens?.refreshToken !== undefined
              ? existingTokens.refreshToken
              : await findToken({
                  userId,
                  identifier: `${identifier}:refresh`,
                });

          if (existingRefreshToken) {
            await updateToken({ userId, identifier: `${identifier}:refresh` }, refreshTokenData);
            logger.debug(`${logPrefix} Updated existing refresh token`);
          } else {
            await createToken(refreshTokenData);
            logger.debug(`${logPrefix} Created new refresh token`);
          }
        } else {
          await createToken(refreshTokenData);
          logger.debug(`${logPrefix} Created refresh token (no update methods available)`);
        }
      }

      /** Store client information if provided */
      if (clientInfo) {
        logger.debug(`${logPrefix} Storing client info:`, {
          client_id: clientInfo.client_id,
          has_client_secret: !!clientInfo.client_secret,
        });
        const encryptedClientInfo = await encryptV2(JSON.stringify(clientInfo));

        const clientInfoData = {
          userId,
          type: 'mcp_oauth_client',
          identifier: `${identifier}:client`,
          token: encryptedClientInfo,
          expiresIn: 365 * 24 * 60 * 60,
          metadata,
        };

        // Check if client info already exists and update if it does
        if (findToken && updateToken) {
          // Use provided existing token state if available, otherwise look it up
          const existingClientInfo =
            existingTokens?.clientInfoToken !== undefined
              ? existingTokens.clientInfoToken
              : await findToken({
                  userId,
                  identifier: `${identifier}:client`,
                });

          if (existingClientInfo) {
            await updateToken({ userId, identifier: `${identifier}:client` }, clientInfoData);
            logger.debug(`${logPrefix} Updated existing client info`);
          } else {
            await createToken(clientInfoData);
            logger.debug(`${logPrefix} Created new client info`);
          }
        } else {
          await createToken(clientInfoData);
          logger.debug(`${logPrefix} Created client info (no update methods available)`);
        }
      }

      logger.debug(`${logPrefix} Stored OAuth tokens successfully`, {
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        hasClientInfo: !!clientInfo,
        clientId: clientInfo?.client_id,
        expiresAt: 'expires_at' in tokens ? tokens.expires_at : 'N/A',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      const logPrefix = this.getLogPrefix(userId, serverName);
      logger.error(`${logPrefix} Failed to store tokens`, {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  /**
   * Retrieves OAuth tokens for an MCP server
   */
  static async getTokens({
    userId,
    serverName,
    findToken,
    createToken,
    updateToken,
    refreshTokens,
  }: GetTokensParams): Promise<MCPOAuthTokens | null> {
    const logPrefix = this.getLogPrefix(userId, serverName);

    logger.debug(`${logPrefix} Retrieving OAuth tokens from storage`, {
      hasRefreshTokensFunction: !!refreshTokens,
      hasCreateToken: !!createToken,
      hasUpdateToken: !!updateToken,
    });

    try {
      const identifier = `mcp:${serverName}`;
      logger.debug(`${logPrefix} Looking up access token with identifier: ${identifier}`);

      // Get access token
      const accessTokenData = await findToken({
        userId,
        type: 'mcp_oauth',
        identifier,
      });

      logger.debug(`${logPrefix} Access token lookup result`, {
        found: !!accessTokenData,
        expiresAt: accessTokenData?.expiresAt?.toISOString(),
        createdAt: accessTokenData?.createdAt?.toISOString(),
      });

      /** Check if access token is missing or expired */
      const isMissing = !accessTokenData;
      const isExpired = accessTokenData?.expiresAt && new Date() >= accessTokenData.expiresAt;

      logger.debug(`${logPrefix} Access token status`, {
        isMissing,
        isExpired,
        needsRefresh: isMissing || isExpired,
      });

      if (isMissing || isExpired) {
        logger.info(
          `${logPrefix} Access token ${isMissing ? 'missing' : 'expired'}, attempting refresh`,
        );

        /** Refresh data if we have a refresh token and refresh function */
        const refreshTokenData = await findToken({
          userId,
          type: 'mcp_oauth_refresh',
          identifier: `${identifier}:refresh`,
        });

        logger.debug(`${logPrefix} Refresh token lookup result`, {
          found: !!refreshTokenData,
          expiresAt: refreshTokenData?.expiresAt?.toISOString(),
        });

        if (!refreshTokenData) {
          logger.info(`${logPrefix} No refresh token available - re-authentication required`, {
            reason: isMissing ? 'access_token_missing' : 'access_token_expired',
          });
          return null;
        }

        if (!refreshTokens) {
          logger.warn(`${logPrefix} Refresh token available but no refresh function provided`, {
            reason: isMissing ? 'access_token_missing' : 'access_token_expired',
          });
          return null;
        }

        if (!createToken) {
          logger.warn(`${logPrefix} Refresh token available but no createToken function provided`, {
            reason: isMissing ? 'access_token_missing' : 'access_token_expired',
          });
          return null;
        }

        try {
          logger.info(`${logPrefix} Starting token refresh using refresh token`);
          const decryptedRefreshToken = await decryptV2(refreshTokenData.token);
          logger.debug(`${logPrefix} Refresh token decrypted successfully`);

          /** Client information if available */
          let clientInfo;
          let clientInfoData;
          try {
            logger.debug(`${logPrefix} Looking up client information`);
            clientInfoData = await findToken({
              userId,
              type: 'mcp_oauth_client',
              identifier: `${identifier}:client`,
            });
            if (clientInfoData) {
              const decryptedClientInfo = await decryptV2(clientInfoData.token);
              clientInfo = JSON.parse(decryptedClientInfo);
              logger.debug(`${logPrefix} Client info retrieved`, {
                clientId: clientInfo.client_id,
                hasClientSecret: !!clientInfo.client_secret,
              });
            } else {
              logger.debug(`${logPrefix} No client info found in storage`);
            }
          } catch (err) {
            logger.debug(`${logPrefix} Error retrieving client info`, {
              error: err instanceof Error ? err.message : String(err),
            });
          }

          const metadata = {
            userId,
            serverName,
            identifier,
            clientInfo,
          };

          logger.debug(`${logPrefix} Calling refresh function`);
          const newTokens = await refreshTokens(decryptedRefreshToken, metadata);
          logger.debug(`${logPrefix} Refresh function returned new tokens`, {
            hasAccessToken: !!newTokens.access_token,
            hasRefreshToken: !!newTokens.refresh_token,
          });

          // Store the refreshed tokens (handles both create and update)
          // Pass existing token state to avoid duplicate DB calls
          logger.debug(`${logPrefix} Storing refreshed tokens`);
          await this.storeTokens({
            userId,
            serverName,
            tokens: newTokens,
            createToken,
            updateToken,
            findToken,
            clientInfo,
            existingTokens: {
              accessToken: accessTokenData, // We know this is expired/missing
              refreshToken: refreshTokenData, // We already have this
              clientInfoToken: clientInfoData, // We already looked this up
            },
          });

          logger.info(`${logPrefix} Token refresh completed successfully`);
          return newTokens;
        } catch (refreshError) {
          logger.error(`${logPrefix} Token refresh failed`, {
            error: refreshError instanceof Error ? refreshError.message : String(refreshError),
            stack: refreshError instanceof Error ? refreshError.stack : undefined,
          });
          // Check if it's an unauthorized_client error (refresh not supported)
          const errorMessage =
            refreshError instanceof Error ? refreshError.message : String(refreshError);
          if (errorMessage.includes('unauthorized_client')) {
            logger.info(`${logPrefix} Server does not support refresh tokens - re-auth required`);
          }
          return null;
        }
      }

      // If we reach here, access token should exist and be valid
      if (!accessTokenData) {
        return null;
      }

      const decryptedAccessToken = await decryptV2(accessTokenData.token);

      /** Get refresh token if available */
      const refreshTokenData = await findToken({
        userId,
        type: 'mcp_oauth_refresh',
        identifier: `${identifier}:refresh`,
      });

      const tokens: MCPOAuthTokens = {
        access_token: decryptedAccessToken,
        token_type: 'Bearer',
        obtained_at: accessTokenData.createdAt.getTime(),
        expires_at: accessTokenData.expiresAt?.getTime(),
      };

      if (refreshTokenData) {
        tokens.refresh_token = await decryptV2(refreshTokenData.token);
      }

      logger.debug(`${logPrefix} Loaded existing OAuth tokens from storage`);
      return tokens;
    } catch (error) {
      logger.error(`${logPrefix} Failed to retrieve tokens`, error);
      return null;
    }
  }

  static async getClientInfoAndMetadata({
    userId,
    serverName,
    findToken,
  }: {
    userId: string;
    serverName: string;
    findToken: TokenMethods['findToken'];
  }): Promise<{
    clientInfo: OAuthClientInformation;
    clientMetadata: Record<string, unknown>;
  } | null> {
    const identifier = `mcp:${serverName}`;

    const clientInfoData: IToken | null = await findToken({
      userId,
      type: 'mcp_oauth_client',
      identifier: `${identifier}:client`,
    });
    if (clientInfoData == null) {
      return null;
    }

    const tokenData = await decryptV2(clientInfoData.token);
    const clientInfo = JSON.parse(tokenData);

    // get metadata from the token as a plain object. While it's defined as a Map in the database type, it's a plain object at runtime.
    function getMetadata(
      metadata: Map<string, unknown> | Record<string, unknown> | null,
    ): Record<string, unknown> {
      if (metadata == null) {
        return {};
      }
      if (metadata instanceof Map) {
        return Object.fromEntries(metadata);
      }
      return { ...(metadata as Record<string, unknown>) };
    }
    const clientMetadata = getMetadata(clientInfoData.metadata ?? null);

    return {
      clientInfo,
      clientMetadata,
    };
  }

  /**
   * Deletes all OAuth-related tokens for a specific user and server
   */
  static async deleteUserTokens({
    userId,
    serverName,
    deleteToken,
  }: {
    userId: string;
    serverName: string;
    deleteToken: (filter: { userId: string; type: string; identifier: string }) => Promise<void>;
  }): Promise<void> {
    const identifier = `mcp:${serverName}`;

    // delete client info token
    await deleteToken({
      userId,
      type: 'mcp_oauth_client',
      identifier: `${identifier}:client`,
    });

    // delete access token
    await deleteToken({
      userId,
      type: 'mcp_oauth',
      identifier,
    });

    // delete refresh token
    await deleteToken({
      userId,
      type: 'mcp_oauth_refresh',
      identifier: `${identifier}:refresh`,
    });
  }
}
