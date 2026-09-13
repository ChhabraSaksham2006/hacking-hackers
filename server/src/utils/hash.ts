import bcrypt from 'bcryptjs';

const PASSWORD_SALT_ROUNDS = 12;
const TOKEN_SALT_ROUNDS = 4;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, PASSWORD_SALT_ROUNDS);
}

export async function comparePassword(
  password: string,
  hash: string,
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Hash a refresh token for storage.
 * Uses a fast hash (lower rounds) since refresh tokens are already
 * cryptographically random — we just need to avoid storing them in plaintext.
 */
export async function hashToken(token: string): Promise<string> {
  return bcrypt.hash(token, TOKEN_SALT_ROUNDS);
}

export async function compareToken(
  token: string,
  hash: string,
): Promise<boolean> {
  return bcrypt.compare(token, hash);
}
