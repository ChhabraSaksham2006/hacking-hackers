import { Server, Socket } from 'socket.io';
import { Server as HttpServer } from 'http';
import { verifyAccessToken } from './utils/jwt.js';
import { corsOptions } from './config/cors.js';

let io: Server;

export function initSocket(httpServer: HttpServer) {
  io = new Server(httpServer, {
    cors: corsOptions,
    transports: ['websocket', 'polling'],
  });

  // Middleware for JWT authentication
  io.use((socket: Socket, next) => {
    let token =
      socket.handshake.auth?.token ||
      socket.handshake.headers['authorization']?.replace(/^Bearer\s+/i, '');
    
    if (!token && socket.handshake.headers.cookie) {
      const match = socket.handshake.headers.cookie.match(/(?:^|;\s*)access_token=([^;]*)/);
      if (match) {
        token = match[1];
      }
    }
    
    if (!token) {
      return next(new Error('Authentication error: Missing token'));
    }

    try {
      const decoded = verifyAccessToken(token);
      
      if (!decoded.orgId) {
        return next(new Error('Authentication error: Missing orgId'));
      }

      // Attach orgId to the socket data for easy access
      socket.data.orgId = decoded.orgId;
      socket.data.userId = decoded.userId;
      socket.data.role = decoded.role;
      next();
    } catch (err) {
      next(new Error('Authentication error: Invalid token'));
    }
  });

  io.on('connection', (socket: Socket) => {
    const { orgId, userId } = socket.data;
    
    // Join the organization-specific room
    const roomName = `org:${orgId}`;
    socket.join(roomName);

    console.log(`🔌 [Socket.io] Client connected (User: ${userId}, Org: ${orgId})`);

    socket.on('disconnect', () => {
      console.log(`🔌 [Socket.io] Client disconnected (User: ${userId}, Org: ${orgId})`);
    });
  });

  console.log('⚡ Socket.io Server Initialized');
}

/**
 * Emits an event to all connected clients in a specific organization's room.
 * @param orgId The organization ID (as string or ObjectId).
 * @param event The event name (e.g. 'alert_created').
 * @param payload The data to send.
 */
export function emitToOrg(orgId: string | { toString(): string }, event: string, payload: any) {
  if (!io) {
    console.warn('[Socket.io] Attempted to emit event before initialization');
    return;
  }
  const orgString = typeof orgId === 'string' ? orgId : orgId.toString();
  console.log(`[Socket.io] Emitting '${event}' to room 'org:${orgString}'`);
  io.to(`org:${orgString}`).emit(event, payload);
}
