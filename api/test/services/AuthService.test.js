// Mock dependencies
jest.mock('~/models', () => ({
  getUserById: jest.fn().mockResolvedValue({
    _id: 'user123',
    email: 'test@example.com',
    username: 'testuser',
  }),
  generateToken: jest.fn().mockResolvedValue('mock-jwt-token'),
  generateRefreshToken: jest.fn().mockResolvedValue('mock-refresh-token'),
  createSession: jest.fn().mockResolvedValue({
    session: {
      _id: 'session123',
      expiration: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
    refreshToken: 'mock-refresh-token',
  }),
}));

jest.mock('@librechat/data-schemas', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('@librechat/api', () => ({
  isEnabled: jest.fn((val) => val === 'true'),
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'signed-jwt-token'),
}));

jest.mock('~/server/services/Config', () => ({
  getAppConfig: jest.fn().mockResolvedValue({}),
}));

describe('AuthService Cookie SameSite Configuration', () => {
  let originalEnv;
  let mockRes;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };

    // Reset mock response object
    mockRes = {
      cookie: jest.fn(),
      status: jest.fn(() => mockRes),
      json: jest.fn(() => mockRes),
    };

    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
    // Clear the module cache to ensure fresh imports
    jest.resetModules();
  });

  describe('setAuthTokens', () => {
    it('should use strict sameSite by default when OIDC_SAME_SITE is not set', async () => {
      // setAuthTokens should use strict by default
      delete process.env.OIDC_SAME_SITE;
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setAuthTokens } = require('~/server/services/AuthService');

      await setAuthTokens('user123', mockRes);

      expect(mockRes.cookie).toHaveBeenCalledTimes(2);

      // Check refreshToken cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        }),
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'librechat',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        }),
      );
    });

    it('should use none sameSite when OIDC_SAME_SITE is set to none', async () => {
      // setAuthTokens should respect OIDC_SAME_SITE env var
      process.env.OIDC_SAME_SITE = 'none';
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setAuthTokens } = require('~/server/services/AuthService');

      await setAuthTokens('user123', mockRes);

      expect(mockRes.cookie).toHaveBeenCalledTimes(2);

      // Check refreshToken cookie - should use 'none'
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        }),
      );

      // Check token_provider cookie - should use 'none'
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'librechat',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        }),
      );
    });

    it('should not use secure flag in non-production environment', async () => {
      delete process.env.OIDC_SAME_SITE;
      process.env.NODE_ENV = 'development';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setAuthTokens } = require('~/server/services/AuthService');

      await setAuthTokens('user123', mockRes);

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: false,
          sameSite: 'strict',
        }),
      );
    });
  });

  describe('setOpenIDAuthTokens', () => {
    const mockTokenset = {
      access_token: 'mock-access-token',
      refresh_token: 'mock-refresh-token',
    };

    it('should use strict sameSite by default when OIDC_SAME_SITE is not set', () => {
      delete process.env.OIDC_SAME_SITE;
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setOpenIDAuthTokens } = require('~/server/services/AuthService');

      setOpenIDAuthTokens(mockTokenset, mockRes);

      expect(mockRes.cookie).toHaveBeenCalledTimes(2);

      // Check refreshToken cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        'mock-refresh-token',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        }),
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'openid',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        }),
      );
    });

    it('should use none sameSite when OIDC_SAME_SITE is set to none', () => {
      process.env.OIDC_SAME_SITE = 'none';
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setOpenIDAuthTokens } = require('~/server/services/AuthService');

      setOpenIDAuthTokens(mockTokenset, mockRes);

      expect(mockRes.cookie).toHaveBeenCalledTimes(2);

      // Check refreshToken cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refreshToken',
        'mock-refresh-token',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        }),
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'openid',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        }),
      );
    });

    it('should include openid_user_id cookie with correct sameSite when OPENID_REUSE_TOKENS is enabled', () => {
      process.env.OIDC_SAME_SITE = 'none';
      process.env.NODE_ENV = 'production';
      process.env.OPENID_REUSE_TOKENS = 'true';
      process.env.JWT_REFRESH_SECRET = 'test-secret';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setOpenIDAuthTokens } = require('~/server/services/AuthService');

      setOpenIDAuthTokens(mockTokenset, mockRes, 'user123');

      expect(mockRes.cookie).toHaveBeenCalledTimes(3);

      // Check openid_user_id cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'openid_user_id',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        }),
      );
    });

    it('should handle missing tokenset gracefully', () => {
      delete process.env.OIDC_SAME_SITE;
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setOpenIDAuthTokens } = require('~/server/services/AuthService');

      const result = setOpenIDAuthTokens(null, mockRes);

      expect(result).toBeUndefined();
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });
  });

  describe('Debug Logging for Cookie Creation', () => {
    it('should log debug information when setting cookies in setAuthTokens', async () => {
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setAuthTokens } = require('~/server/services/AuthService');
      const mockLogger = require('@librechat/data-schemas').logger;

      await setAuthTokens('user123', mockRes);

      // Verify logger.debug was called for both cookies
      expect(mockLogger.debug).toHaveBeenCalledTimes(2);

      // Check first debug log for refreshToken
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[setAuthTokens] Setting refresh token cookie',
        expect.objectContaining({
          event: 'setting_refresh_cookie',
          cookieName: 'refreshToken',
          tokenPreview: expect.stringMatching(/^.{8}\.\.\./), // First 8 chars + '...'
          expires: expect.any(String),
          httpOnly: true,
          secure: true,
          sameSite: 'strict', // Default value when OIDC_SAME_SITE is not set
        }),
      );

      // Check second debug log for token_provider
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[setAuthTokens] Setting token_provider cookie',
        expect.objectContaining({
          event: 'setting_refresh_cookie',
          cookieName: 'token_provider',
          tokenPreview: 'librecha...', // First 8 chars of 'librechat' + '...'
          expires: expect.any(String),
          httpOnly: true,
          secure: true,
          sameSite: 'strict', // Default value when OIDC_SAME_SITE is not set
          token_provider: 'librechat',
        }),
      );
    });

    it('should log debug information when setting cookies in setOpenIDAuthTokens', () => {
      process.env.NODE_ENV = 'production';
      process.env.OIDC_SAME_SITE = 'none';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setOpenIDAuthTokens } = require('~/server/services/AuthService');
      const mockLogger = require('@librechat/data-schemas').logger;

      const mockTokenset = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token-12345',
      };

      setOpenIDAuthTokens(mockTokenset, mockRes);

      // Verify logger.debug was called for both cookies
      expect(mockLogger.debug).toHaveBeenCalledTimes(2);

      // Check first debug log for refreshToken
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[setOpenIDAuthTokens] Setting refresh token cookie',
        expect.objectContaining({
          event: 'setting_refresh_cookie',
          cookieName: 'refreshToken',
          tokenPreview: 'mock-ref...', // First 8 chars of refresh_token
          expires: expect.any(String),
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        }),
      );

      // Check second debug log for token_provider
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[setOpenIDAuthTokens] Setting token_provider cookie',
        expect.objectContaining({
          event: 'setting_refresh_cookie',
          cookieName: 'token_provider',
          tokenPreview: 'openid...', // First 8 chars (6 in this case) of 'openid' + '...'
          expires: expect.any(String),
          httpOnly: true,
          secure: true,
          sameSite: 'none',
          token_provider: 'openid',
        }),
      );
    });

    it('should log debug information for openid_user_id cookie when OPENID_REUSE_TOKENS is enabled', () => {
      process.env.NODE_ENV = 'production';
      process.env.OIDC_SAME_SITE = 'lax';
      process.env.OPENID_REUSE_TOKENS = 'true';
      process.env.JWT_REFRESH_SECRET = 'test-secret';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setOpenIDAuthTokens } = require('~/server/services/AuthService');
      const mockLogger = require('@librechat/data-schemas').logger;

      const mockTokenset = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
      };

      setOpenIDAuthTokens(mockTokenset, mockRes, 'user123');

      // Verify logger.debug was called for all three cookies
      expect(mockLogger.debug).toHaveBeenCalledTimes(3);

      // Check third debug log for openid_user_id
      expect(mockLogger.debug).toHaveBeenCalledWith(
        '[setOpenIDAuthTokens] Setting openid_user_id cookie',
        expect.objectContaining({
          event: 'setting_refresh_cookie',
          cookieName: 'openid_user_id',
          tokenPreview: expect.stringMatching(/^.{8}\.\.\./), // First 8 chars + '...'
          expires: expect.any(String),
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
        }),
      );
    });

    it('should not log full tokens, only safe previews', async () => {
      process.env.NODE_ENV = 'production';

      // Re-import to get fresh module with current env
      jest.resetModules();
      const { setAuthTokens } = require('~/server/services/AuthService');
      const mockLogger = require('@librechat/data-schemas').logger;

      await setAuthTokens('user123', mockRes);

      // Get all debug calls
      const debugCalls = mockLogger.debug.mock.calls;

      // Verify no call contains the full mock token
      debugCalls.forEach((call) => {
        const logData = JSON.stringify(call);
        // The mock token is 'mock-refresh-token', we should only see 'mock-ref...'
        expect(logData).not.toContain('mock-refresh-token');
        if (logData.includes('tokenPreview')) {
          // Ensure preview is at most 11 characters (8 chars + '...')
          const match = logData.match(/"tokenPreview":"([^"]+)"/);
          if (match && match[1] !== 'librechat' && match[1] !== 'openid') {
            expect(match[1].length).toBeLessThanOrEqual(11);
          }
        }
      });
    });
  });
});
