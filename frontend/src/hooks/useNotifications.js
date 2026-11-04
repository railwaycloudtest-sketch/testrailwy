import { useEffect, useState, useCallback } from "react";
import { getUnreadNotifications, markNotificationsViewed } from "../lib/api";

const useNotifications = () => {
  const [unreadCount, setUnreadCount] = useState(0);

  const fetchCount = useCallback(async () => {
    try {
      const count = await getUnreadNotifications();
      setUnreadCount(count);
    } catch {}
  }, []);

  useEffect(() => {
    fetchCount();
    const interval = setInterval(fetchCount, 10000);
    return () => clearInterval(interval);
  }, [fetchCount]);

  const resetCount = useCallback(() => {
    markNotificationsViewed().catch(() => {});
    setUnreadCount(0);
  }, []);

  return { unreadCount, resetCount };
};

export default useNotifications;
