import { useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuthMe } from './useApi';
import { apiFetch } from '@/lib/api';
import { onPageActivityChange } from '@/lib/pageActivity';

let socketInstance: Socket | null = null;
let stopActivityWatch: (() => void) | null = null;

/**
 * Disconnect the socket while the tab is inactive (hidden > grace period) and
 * reconnect when the user comes back. An open socket counts as an active
 * viewer on the backend and keeps the replay ticker running for the org.
 */
function watchPageActivity() {
  if (stopActivityWatch) return;
  stopActivityWatch = onPageActivityChange(
    () => {
      if (socketInstance && !socketInstance.connected) socketInstance.connect();
    },
    () => {
      if (socketInstance?.connected) socketInstance.disconnect();
    },
  );
}

function stopWatchingPageActivity() {
  stopActivityWatch?.();
  stopActivityWatch = null;
}

/**
 * Determine backend Socket.io URL:
 * - Localhost: undefined (Vite proxy at http://localhost:8080/socket.io).
 * - Production: Direct connection to Render backend (wss://...) because Vercel edge proxy
 *   does not support persistent WebSockets and corrupts long-polling response encoding.
 */
function getSocketUrl(): string | undefined {
  if (typeof window === 'undefined') return undefined;
  const isLocalhost =
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1';
  if (isLocalhost) return undefined;

  return (
    import.meta.env['VITE_API_URL'] ||
    'https://flow-drishti-server.onrender.com'
  ).trim().replace(/\/$/, '');
}

export function useSocket() {
  const { data: user } = useAuthMe();
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // If no user is logged in, disconnect any active socket
    if (!user) {
      stopWatchingPageActivity();
      if (socketInstance) {
        socketInstance.disconnect();
        socketInstance = null;
      }
      setIsConnected(false);
      return;
    }

    if (!socketInstance) {
      const socketUrl = getSocketUrl();

      socketInstance = io(socketUrl, {
        auth: (cb) => {
          // Dynamic auth callback: retrieves a fresh signed socket token from backend
          // using the secure session cookie. Automatically invoked on connect and reconnections.
          apiFetch<{ token: string }>('/api/auth/socket-token')
            .then((res) => cb({ token: res.token }))
            .catch((err) => {
              console.warn('[Socket.io] Failed to obtain socket token:', err?.message || err);
              cb({});
            });
        },
        transports: ['websocket', 'polling'],
        withCredentials: true,
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: Infinity,
      });
    }

    watchPageActivity();

    // Set initial connection state based on current socket state
    setIsConnected(socketInstance.connected);

    const onConnect = () => setIsConnected(true);
    const onDisconnect = () => setIsConnected(false);
    const onError = (err: Error) => {
      console.warn('Socket connection error:', err.message);
      setIsConnected(false);
    };

    socketInstance.on('connect', onConnect);
    socketInstance.on('disconnect', onDisconnect);
    socketInstance.on('connect_error', onError);

    return () => {
      if (socketInstance) {
        socketInstance.off('connect', onConnect);
        socketInstance.off('disconnect', onDisconnect);
        socketInstance.off('connect_error', onError);
      }
    };
  }, [user]);

  return { socket: socketInstance, isConnected };
}

export function disconnectSocket() {
  stopWatchingPageActivity();
  if (socketInstance) {
    socketInstance.disconnect();
    socketInstance = null;
  }
}

