const { setAuthTokens, setOpenIDAuthTokens } = require('~/server/services/AuthService');

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
      // Delete the env variable to test default
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
        })
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'librechat',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        })
      );
    });

    it('should use none sameSite when OIDC_SAME_SITE is set to none', async () => {
      process.env.OIDC_SAME_SITE = 'none';
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
          sameSite: 'none',
        })
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'librechat',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        })
      );
    });

    it('should use lax sameSite when OIDC_SAME_SITE is set to lax', async () => {
      process.env.OIDC_SAME_SITE = 'lax';
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
          sameSite: 'lax',
        })
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
        })
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
        })
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'openid',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        })
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
        })
      );

      // Check token_provider cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'token_provider',
        'openid',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        })
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
        })
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
});
