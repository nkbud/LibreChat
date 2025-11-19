import { logger } from '@librechat/data-schemas';
import { ErrorTypes } from 'librechat-data-provider';
import type { IUser, UserMethods } from '@librechat/data-schemas';

/**
 * Finds or migrates a user for OpenID authentication
 * @returns user object (with migration fields if needed), error message, and whether migration is needed
 */
export async function findOpenIDUser({
  openidId,
  findUser,
  email,
  idOnTheSource,
  strategyName = 'openid',
}: {
  openidId: string;
  findUser: UserMethods['findUser'];
  email?: string;
  idOnTheSource?: string;
  strategyName?: string;
}): Promise<{ user: IUser | null; error: string | null; migration: boolean }> {
  logger.debug(`[${strategyName}] Starting user lookup`, {
    event: 'find_openid_user_start',
    openidId: openidId,
    email: email,
    idOnTheSource: idOnTheSource,
    strategyName: strategyName,
  });

  const primaryConditions = [];

  if (openidId && typeof openidId === 'string') {
    primaryConditions.push({ openidId });
  }

  if (idOnTheSource && typeof idOnTheSource === 'string') {
    primaryConditions.push({ idOnTheSource });
  }

  logger.debug(`[${strategyName}] Primary lookup conditions prepared`, {
    event: 'find_openid_user_conditions',
    conditionCount: primaryConditions.length,
    hasOpenidId: !!openidId,
    hasIdOnTheSource: !!idOnTheSource,
  });

  let user = null;
  if (primaryConditions.length > 0) {
    user = await findUser({ $or: primaryConditions });
    logger.debug(`[${strategyName}] Primary lookup result`, {
      event: 'find_openid_user_primary_lookup',
      userFound: !!user,
      userId: user?._id,
    });
  }
  if (!user && email) {
    logger.debug(`[${strategyName}] Attempting email-based lookup`, {
      event: 'find_openid_user_email_lookup',
      email: email,
    });

    user = await findUser({ email });
    logger.warn(
      `[${strategyName}] user ${user ? 'found' : 'not found'} with email: ${email} for openidId: ${openidId}`,
      {
        event: 'find_openid_user_email_result',
        userFound: !!user,
        userId: user?._id,
        email: email,
        openidId: openidId,
      },
    );

    // If user found by email, check if they're allowed to use OpenID provider
    if (user && user.provider && user.provider !== 'openid') {
      logger.warn(
        `[${strategyName}] Attempted OpenID login by user ${user.email}, was registered with "${user.provider}" provider`,
        {
          event: 'find_openid_user_provider_mismatch',
          email: user.email,
          existingProvider: user.provider,
          attemptedProvider: 'openid',
        },
      );
      return { user: null, error: ErrorTypes.AUTH_FAILED, migration: false };
    }

    // If user found by email but doesn't have openidId, prepare for migration
    if (user && !user.openidId) {
      logger.info(
        `[${strategyName}] Preparing user ${user.email} for migration to OpenID with sub: ${openidId}`,
        {
          event: 'find_openid_user_migration',
          email: user.email,
          userId: user._id,
          openidId: openidId,
        },
      );
      user.provider = 'openid';
      user.openidId = openidId;
      return { user, error: null, migration: true };
    }
  }

  logger.debug(`[${strategyName}] User lookup complete`, {
    event: 'find_openid_user_complete',
    userFound: !!user,
    userId: user?._id,
  });

  return { user, error: null, migration: false };
}
