import { useEffect, useState, useCallback } from "react";
import { sendHeartbeat, getOnlineUsers } from "../lib/api";

const useOnlineStatus = () => {
  const [onlineUserIds, setOnlineUserIds] = useState(new Set());
  const [onlineUsersMap, setOnlineUsersMap] = useState(new Map());

  const fetchOnline = useCallback(async () => {
    try {
      const users = await getOnlineUsers();
      const ids = new Set();
      const map = new Map();
      for (const u of users) {
        ids.add(u._id);
        map.set(u._id, u.lastSeen);
      }
      setOnlineUserIds(ids);
      setOnlineUsersMap(map);
    } catch {}
  }, []);

  useEffect(() => {
    sendHeartbeat().catch(() => {});
    fetchOnline();

    const heartbeatInterval = setInterval(() => {
      sendHeartbeat().catch(() => {});
    }, 20000);

    const pollInterval = setInterval(fetchOnline, 30000);

    return () => {
      clearInterval(heartbeatInterval);
      clearInterval(pollInterval);
    };
  }, [fetchOnline]);

  return { onlineUserIds, onlineUsersMap };
};

export default useOnlineStatus;
