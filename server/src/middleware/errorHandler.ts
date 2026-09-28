import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { env } from '../config/env.js';

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public isOperational = true,
  ) {
    super(message);
    this.name = 'AppError';
    Error.captureStackTrace(this, this.constructor);
  }
}

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  // Zod validation errors
  if (err instanceof ZodError) {
    const firstIssue = err.issues[0]?.message || 'Request validation failed';
    res.status(400).json({
      error: firstIssue,
      message: firstIssue,
      code: 'VALIDATION_ERROR',
      details: err.issues.map((i) => ({
        path: i.path.join('.'),
        message: i.message,
      })),
    });
    return;
  }

  // Known operational errors
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: err.message,
      message: err.message,
      statusCode: err.statusCode,
    });
    return;
  }

  // Mongoose duplicate key
  if (err.name === 'MongoServerError' && (err as any).code === 11000) {
    res.status(409).json({
      error: 'A record with that value already exists',
      message: 'A record with that value already exists',
      statusCode: 409,
    });
    return;
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    res.status(400).json({
      error: err.message,
      message: err.message,
      statusCode: 400,
    });
    return;
  }

  // Unknown errors
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message:
      env.NODE_ENV === 'production'
        ? err.message + (err.stack ? '\n' + err.stack : '')
        : err.message,
    statusCode: 500,
  });
}
