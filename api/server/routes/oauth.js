// file deepcode ignore NoRateLimitingForLogin: Rate limiting is handled by the `loginLimiter` middleware
const express = require('express');
const passport = require('passport');
const { randomState } = require('openid-client');
const { logger } = require('@librechat/data-schemas');
const { ErrorTypes } = require('librechat-data-provider');
const { isEnabled, createSetBalanceConfig } = require('@librechat/api');
const { checkDomainAllowed, loginLimiter, logHeaders, checkBan } = require('~/server/middleware');
const { syncUserEntraGroupMemberships } = require('~/server/services/PermissionService');
const { setAuthTokens, setOpenIDAuthTokens } = require('~/server/services/AuthService');
const { getAppConfig } = require('~/server/services/Config');
const { Balance } = require('~/db/models');

const setBalanceConfig = createSetBalanceConfig({
  getAppConfig,
  Balance,
});

const router = express.Router();

const domains = {
  client: process.env.DOMAIN_CLIENT,
  server: process.env.DOMAIN_SERVER,
};

router.use(logHeaders);
router.use(loginLimiter);

const oauthHandler = async (req, res, next) => {
  try {
    logger.debug('[oauthHandler] Starting OAuth callback handler', {
      event: 'oauth_handler_start',
      hasUser: !!req.user,
      userProvider: req.user?.provider,
      userId: req.user?._id,
      headersSent: res.headersSent,
    });

    if (res.headersSent) {
      logger.warn('[oauthHandler] Headers already sent, aborting', {
        event: 'oauth_handler_headers_sent',
      });
      return;
    }

    await checkBan(req, res);
    if (req.banned) {
      logger.warn('[oauthHandler] User is banned', {
        event: 'oauth_handler_user_banned',
        userId: req.user?._id,
        email: req.user?.email,
      });
      return;
    }
    if (
      req.user &&
      req.user.provider == 'openid' &&
      isEnabled(process.env.OPENID_REUSE_TOKENS) === true
    ) {
      logger.debug('[oauthHandler] Using OpenID token reuse flow', {
        event: 'oauth_handler_openid_reuse',
        userId: req.user._id,
        hasTokenset: !!req.user.tokenset,
        hasAccessToken: !!req.user.tokenset?.access_token,
        hasRefreshToken: !!req.user.tokenset?.refresh_token,
      });

      await syncUserEntraGroupMemberships(req.user, req.user.tokenset.access_token);
      setOpenIDAuthTokens(req.user.tokenset, res, req.user._id.toString());

      logger.debug('[oauthHandler] OpenID tokens set, redirecting to client', {
        event: 'oauth_handler_openid_redirect',
        redirectUrl: domains.client,
      });
    } else {
      logger.debug('[oauthHandler] Using standard auth token flow', {
        event: 'oauth_handler_standard_auth',
        userId: req.user._id,
        provider: req.user?.provider,
      });

      await setAuthTokens(req.user._id, res);

      logger.debug('[oauthHandler] Standard tokens set, redirecting to client', {
        event: 'oauth_handler_standard_redirect',
        redirectUrl: domains.client,
      });
    }
    res.redirect(domains.client);
  } catch (err) {
    logger.error('Error in setting authentication tokens:', {
      event: 'oauth_handler_error',
      error: err.message,
      stack: err.stack,
      errorType: err.constructor.name,
      userId: req.user?._id,
    });
    next(err);
  }
};

router.get('/error', (req, res) => {
  /** A single error message is pushed by passport when authentication fails. */
  const errorMessage = req.session?.messages?.pop() || 'Unknown error';
  logger.error('Error in OAuth authentication:', {
    event: 'oauth_error',
    message: errorMessage,
    sessionId: req.session?.id,
    hasSession: !!req.session,
    sessionMessages: req.session?.messages,
  });

  res.redirect(`${domains.client}/login?redirect=false&error=${ErrorTypes.AUTH_FAILED}`);
});

/**
 * Google Routes
 */
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['openid', 'profile', 'email'],
    session: false,
  }),
);

router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
    scope: ['openid', 'profile', 'email'],
  }),
  setBalanceConfig,
  checkDomainAllowed,
  oauthHandler,
);

/**
 * Facebook Routes
 */
router.get(
  '/facebook',
  passport.authenticate('facebook', {
    scope: ['public_profile'],
    profileFields: ['id', 'email', 'name'],
    session: false,
  }),
);

router.get(
  '/facebook/callback',
  passport.authenticate('facebook', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
    scope: ['public_profile'],
    profileFields: ['id', 'email', 'name'],
  }),
  setBalanceConfig,
  checkDomainAllowed,
  oauthHandler,
);

/**
 * OpenID Routes
 */
router.get('/openid', (req, res, next) => {
  logger.debug('[OpenID] Starting OpenID authentication request', {
    event: 'openid_auth_start',
    sessionId: req.session?.id,
    hasSession: !!req.session,
  });

  return passport.authenticate('openid', {
    session: false,
    state: randomState(),
  })(req, res, next);
});

router.get(
  '/openid/callback',
  passport.authenticate('openid', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
  }),
  setBalanceConfig,
  checkDomainAllowed,
  (req, res, next) => {
    logger.debug('[OpenID] Callback received, processing', {
      event: 'openid_callback_received',
      hasUser: !!req.user,
      userId: req.user?._id,
    });
    oauthHandler(req, res, next);
  },
);

/**
 * GitHub Routes
 */
router.get(
  '/github',
  passport.authenticate('github', {
    scope: ['user:email', 'read:user'],
    session: false,
  }),
);

router.get(
  '/github/callback',
  passport.authenticate('github', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
    scope: ['user:email', 'read:user'],
  }),
  setBalanceConfig,
  checkDomainAllowed,
  oauthHandler,
);

/**
 * Discord Routes
 */
router.get(
  '/discord',
  passport.authenticate('discord', {
    scope: ['identify', 'email'],
    session: false,
  }),
);

router.get(
  '/discord/callback',
  passport.authenticate('discord', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
    scope: ['identify', 'email'],
  }),
  setBalanceConfig,
  checkDomainAllowed,
  oauthHandler,
);

/**
 * Apple Routes
 */
router.get(
  '/apple',
  passport.authenticate('apple', {
    session: false,
  }),
);

router.post(
  '/apple/callback',
  passport.authenticate('apple', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
  }),
  setBalanceConfig,
  checkDomainAllowed,
  oauthHandler,
);

/**
 * SAML Routes
 */
router.get(
  '/saml',
  passport.authenticate('saml', {
    session: false,
  }),
);

router.post(
  '/saml/callback',
  passport.authenticate('saml', {
    failureRedirect: `${domains.client}/oauth/error`,
    failureMessage: true,
    session: false,
  }),
  oauthHandler,
);

module.exports = router;
