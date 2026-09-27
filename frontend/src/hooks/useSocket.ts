import { useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuthMe } from './useApi';

let socketInstance: Socket | null = null;

export function useSocket() {
  const { data: user } = useAuthMe();
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // If no user is logged in, don't connect
    if (!user) return;

    if (!socketInstance) {
      const serverUrl = import.meta.env['VITE_API_URL'];
      
      socketInstance = io(serverUrl || undefined, {
        withCredentials: true,
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: Infinity
      });
    }

    // Set initial connection state based on the current socket state
    setIsConnected(socketInstance.connected);

    const onConnect = () => setIsConnected(true);
    const onDisconnect = () => setIsConnected(false);
    const onError = (err: Error) => {
      console.error('Socket connection error:', err.message);
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
  if (socketInstance) {
    socketInstance.disconnect();
    socketInstance = null;
  }
}
