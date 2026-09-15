import { useEffect, useState } from "react";
import { Bell, Check, Trash2, AlertTriangle, Info, AlertCircle } from "lucide-react";
import { useNotifications, useMarkNotificationRead, useMarkAllNotificationsRead } from "@/hooks/useApi";
import { useSocket } from "@/hooks/useSocket";
import { useQueryClient } from "@tanstack/react-query";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { Link } from "@tanstack/react-router";

function NotificationIcon({ severity }: { severity: string }) {
  switch (severity) {
    case "critical":
      return <AlertTriangle className="size-4 text-crimson" />;
    case "warning":
      return <AlertCircle className="size-4 text-amber-500" />;
    default:
      return <Info className="size-4 text-teal" />;
  }
}

export function NotificationBell() {
  const { data: notifications = [] } = useNotifications();
  const markRead = useMarkNotificationRead();
  const markAllRead = useMarkAllNotificationsRead();
  const { socket } = useSocket();
  const queryClient = useQueryClient();
  const [isOpen, setIsOpen] = useState(false);

  const unreadCount = notifications.filter(n => !n.isRead).length;

  useEffect(() => {
    if (!socket) return;
    
    const handleNewNotif = () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
    };

    socket.on("notification_created", handleNewNotif);
    
    return () => {
      socket.off("notification_created", handleNewNotif);
    };
  }, [socket, queryClient]);

  return (
    <Popover open={isOpen} onOpenChange={setIsOpen}>
      <PopoverTrigger asChild>
        <button className="relative flex size-8 items-center justify-center rounded-full text-fog hover:bg-void-800 hover:text-paper transition-colors">
          <Bell className="size-[18px]" strokeWidth={2} />
          {unreadCount > 0 && (
            <span className="absolute right-0 top-0 flex size-4 items-center justify-center rounded-full bg-crimson text-[10px] font-bold text-white ring-2 ring-void-900">
              {unreadCount > 9 ? "9+" : unreadCount}
            </span>
          )}
        </button>
      </PopoverTrigger>
      
      <PopoverContent align="end" className="w-[380px] p-0 border-fog-deep/50 bg-void-800/95 backdrop-blur-xl">
        <div className="flex items-center justify-between border-b border-fog-deep/50 px-4 py-3">
          <h3 className="font-semibold text-paper">Notifications</h3>
          {unreadCount > 0 && (
            <button
              onClick={() => markAllRead.mutate()}
              disabled={markAllRead.isPending}
              className="text-[12px] font-medium text-teal hover:text-teal-400 transition-colors flex items-center gap-1"
            >
              <Check className="size-3" /> Mark all read
            </button>
          )}
        </div>
        
        <ScrollArea className="max-h-[400px]">
          {notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <Bell className="size-8 text-fog-deep mb-2" />
              <p className="text-[13px] text-fog">You're all caught up!</p>
            </div>
          ) : (
            <div className="flex flex-col">
              {notifications.map((n) => (
                <div
                  key={n._id}
                  className={cn(
                    "relative flex gap-3 border-b border-fog-deep/30 px-4 py-3 hover:bg-void-700/50 transition-colors group",
                    !n.isRead ? "bg-void-700/20" : ""
                  )}
                >
                  {!n.isRead && (
                    <span className="absolute left-1.5 top-5 size-1.5 rounded-full bg-teal" />
                  )}
                  
                  <div className="mt-0.5 shrink-0">
                    <NotificationIcon severity={n.severity} />
                  </div>
                  
                  <div className="flex flex-1 flex-col gap-1">
                    <p className="text-[14px] font-medium text-paper leading-snug">
                      {n.title}
                    </p>
                    <p className="text-[13px] text-fog line-clamp-2 leading-relaxed">
                      {n.message}
                    </p>
                    <div className="mt-1 flex items-center gap-3 text-[11px] text-fog-deep">
                      <span>{new Date(n.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      {n.alertId && (
                        <Link 
                          to="/app/alerts" 
                          onClick={() => setIsOpen(false)}
                          className="text-teal/80 hover:text-teal"
                        >
                          View alert
                        </Link>
                      )}
                    </div>
                  </div>
                  
                  {!n.isRead && (
                    <button
                      onClick={() => markRead.mutate(n._id)}
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 p-1 text-fog hover:text-teal transition-all"
                      title="Mark as read"
                    >
                      <Check className="size-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </PopoverContent>
    </Popover>
  );
}
