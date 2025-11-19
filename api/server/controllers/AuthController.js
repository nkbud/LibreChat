const cookies = require('cookie');
const jwt = require('jsonwebtoken');
const openIdClient = require('openid-client');
const { logger } = require('@librechat/data-schemas');
const { isEnabled, findOpenIDUser } = require('@librechat/api');
const {
  requestPasswordReset,
  setOpenIDAuthTokens,
  resetPassword,
  setAuthTokens,
  registerUser,
} = require('~/server/services/AuthService');
const { findUser, getUserById, deleteAllUserSessions, findSession } = require('~/models');
const { getGraphApiToken } = require('~/server/services/GraphTokenService');
const { getOAuthReconnectionManager } = require('~/config');
const { getOpenIdConfig } = require('~/strategies');

const registrationController = async (req, res) => {
  try {
    const response = await registerUser(req.body);
    const { status, message } = response;
    res.status(status).send({ message });
  } catch (err) {
    logger.error('[registrationController]', err);
    return res.status(500).json({ message: err.message });
  }
};

const resetPasswordRequestController = async (req, res) => {
  try {
    const resetService = await requestPasswordReset(req);
    if (resetService instanceof Error) {
      return res.status(400).json(resetService);
    } else {
      return res.status(200).json(resetService);
    }
  } catch (e) {
    logger.error('[resetPasswordRequestController]', e);
    return res.status(400).json({ message: e.message });
  }
};

const resetPasswordController = async (req, res) => {
  try {
    const resetPasswordService = await resetPassword(
      req.body.userId,
      req.body.token,
      req.body.password,
    );
    if (resetPasswordService instanceof Error) {
      return res.status(400).json(resetPasswordService);
    } else {
      await deleteAllUserSessions({ userId: req.body.userId });
      return res.status(200).json(resetPasswordService);
    }
  } catch (e) {
    logger.error('[resetPasswordController]', e);
    return res.status(400).json({ message: e.message });
  }
};

const refreshController = async (req, res) => {
  const refreshToken = req.headers.cookie ? cookies.parse(req.headers.cookie).refreshToken : null;
  const token_provider = req.headers.cookie
    ? cookies.parse(req.headers.cookie).token_provider
    : null;

  logger.debug('[refreshController] Starting refresh token request', {
    event: 'refresh_start',
    hasRefreshToken: !!refreshToken,
    tokenProvider: token_provider,
    hasCookies: !!req.headers.cookie,
  });

  if (!refreshToken) {
    logger.warn('[refreshController] Refresh token not provided', {
      event: 'refresh_no_token',
    });
    return res.status(200).send('Refresh token not provided');
  }
  if (token_provider === 'openid' && isEnabled(process.env.OPENID_REUSE_TOKENS) === true) {
    try {
      logger.debug('[refreshController] Using OpenID token refresh flow', {
        event: 'refresh_openid_start',
      });

      const openIdConfig = getOpenIdConfig();
      const tokenset = await openIdClient.refreshTokenGrant(openIdConfig, refreshToken);

      logger.debug('[refreshController] OpenID token grant successful', {
        event: 'refresh_openid_grant_success',
        hasAccessToken: !!tokenset.access_token,
        hasRefreshToken: !!tokenset.refresh_token,
        hasIdToken: !!tokenset.id_token,
      });

      const claims = tokenset.claims();

      logger.debug('[refreshController] Extracted claims from refreshed token', {
        event: 'refresh_openid_claims_extracted',
        sub: claims.sub,
        email: claims.email,
        oid: claims.oid,
      });

      const { user, error } = await findOpenIDUser({
        findUser,
        email: claims.email,
        openidId: claims.sub,
        idOnTheSource: claims.oid,
        strategyName: 'refreshController',
      });

      logger.debug('[refreshController] User lookup for refresh completed', {
        event: 'refresh_openid_user_lookup',
        userFound: !!user,
        userId: user?._id,
        error: error,
      });

      if (error || !user) {
        logger.error('[refreshController] User not found or error during refresh', {
          event: 'refresh_openid_user_error',
          error: error,
          hasUser: !!user,
        });
        return res.status(401).redirect('/login');
      }

      const token = setOpenIDAuthTokens(tokenset, res, user._id.toString());

      logger.info('[refreshController] OpenID token refresh successful', {
        event: 'refresh_openid_success',
        userId: user._id,
        email: user.email,
      });

      return res.status(200).send({ token, user });
    } catch (error) {
      logger.error('[refreshController] OpenID token refresh error', {
        event: 'refresh_openid_error',
        error: error.message,
        stack: error.stack,
        errorType: error.constructor.name,
      });
      return res.status(403).send('Invalid OpenID refresh token');
    }
  }
  try {
    logger.debug('[refreshController] Using standard token refresh flow', {
      event: 'refresh_standard_start',
    });

    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    logger.debug('[refreshController] JWT refresh token verified', {
      event: 'refresh_jwt_verified',
      userId: payload.id,
      exp: payload.exp,
      iat: payload.iat,
    });

    const user = await getUserById(payload.id, '-password -__v -totpSecret -backupCodes');
    if (!user) {
      logger.warn('[refreshController] User not found for refresh token', {
        event: 'refresh_user_not_found',
        userId: payload.id,
      });
      return res.status(401).redirect('/login');
    }

    const userId = payload.id;

    if (process.env.NODE_ENV === 'CI') {
      logger.debug('[refreshController] CI environment, skipping session check', {
        event: 'refresh_ci_mode',
      });
      const token = await setAuthTokens(userId, res);
      return res.status(200).send({ token, user });
    }

    /** Session with the hashed refresh token */
    logger.debug('[refreshController] Looking up session', {
      event: 'refresh_session_lookup',
      userId: userId,
    });

    const session = await findSession(
      {
        userId: userId,
        refreshToken: refreshToken,
      },
      { lean: false },
    );

    logger.debug('[refreshController] Session lookup result', {
      event: 'refresh_session_found',
      hasSession: !!session,
      sessionValid: session && session.expiration > new Date(),
      sessionExpiration: session?.expiration,
    });

    if (session && session.expiration > new Date()) {
      logger.debug('[refreshController] Generating new tokens from session', {
        event: 'refresh_token_generation',
        sessionId: session._id,
      });

      const token = await setAuthTokens(userId, res, session);

      // trigger OAuth MCP server reconnection asynchronously (best effort)
      try {
        void getOAuthReconnectionManager()
          .reconnectServers(userId)
          .catch((err) => {
            logger.error('[refreshController] Error reconnecting OAuth MCP servers:', err);
          });
      } catch (err) {
        logger.warn(`[refreshController] Cannot attempt OAuth MCP servers reconnection:`, err);
      }

      logger.info('[refreshController] Token refresh successful', {
        event: 'refresh_success',
        userId: userId,
      });

      res.status(200).send({ token, user });
    } else if (req?.query?.retry) {
      // Retrying from a refresh token request that failed (401)
      logger.warn('[refreshController] Refresh retry with no session', {
        event: 'refresh_retry_no_session',
        userId: userId,
      });
      res.status(403).send('No session found');
    } else if (payload.exp < Date.now() / 1000) {
      logger.warn('[refreshController] Refresh token expired', {
        event: 'refresh_token_expired',
        userId: userId,
        exp: payload.exp,
        now: Date.now() / 1000,
      });
      res.status(403).redirect('/login');
    } else {
      logger.warn('[refreshController] Session not found or expired', {
        event: 'refresh_session_invalid',
        userId: userId,
        hasSession: !!session,
      });
      res.status(401).send('Refresh token expired or not found for this user');
    }
  } catch (err) {
    logger.error(`[refreshController] Invalid refresh token:`, {
      event: 'refresh_error',
      error: err.message,
      stack: err.stack,
      errorType: err.constructor.name,
    });
    res.status(403).send('Invalid refresh token');
  }
};

const graphTokenController = async (req, res) => {
  try {
    // Validate user is authenticated via Entra ID
    if (!req.user.openidId || req.user.provider !== 'openid') {
      return res.status(403).json({
        message: 'Microsoft Graph access requires Entra ID authentication',
      });
    }

    // Check if OpenID token reuse is active (required for on-behalf-of flow)
    if (!isEnabled(process.env.OPENID_REUSE_TOKENS)) {
      return res.status(403).json({
        message: 'SharePoint integration requires OpenID token reuse to be enabled',
      });
    }

    // Extract access token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        message: 'Valid authorization token required',
      });
    }

    // Get scopes from query parameters
    const scopes = req.query.scopes;
    if (!scopes) {
      return res.status(400).json({
        message: 'Graph API scopes are required as query parameter',
      });
    }

    const accessToken = authHeader.substring(7); // Remove 'Bearer ' prefix
    const tokenResponse = await getGraphApiToken(req.user, accessToken, scopes);

    res.json(tokenResponse);
  } catch (error) {
    logger.error('[graphTokenController] Failed to obtain Graph API token:', error);
    res.status(500).json({
      message: 'Failed to obtain Microsoft Graph token',
    });
  }
};

module.exports = {
  refreshController,
  registrationController,
  resetPasswordController,
  resetPasswordRequestController,
  graphTokenController,
};
