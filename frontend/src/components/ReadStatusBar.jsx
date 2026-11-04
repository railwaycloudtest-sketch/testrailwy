import { useEffect, useState } from "react";
import { useChannelStateContext } from "stream-chat-react";
import { CheckCheckIcon } from "lucide-react";

const ReadStatusBar = () => {
  const { channel } = useChannelStateContext();
  const [seen, setSeen] = useState(false);

  const computeSeen = (ch) => {
    const myId = ch.getClient().user?.id;
    const own = ch.state.messages.filter((m) => m.user_id === myId && m.text);
    const lastOwn = own[own.length - 1];
    if (!lastOwn) return false;

    const stamp = new Date(
      lastOwn.updated_at || lastOwn.created_at
    ).getTime();

    return Object.entries(ch.state.read || {}).some(([uid, v]) => {
      if (uid === myId) return false;
      return new Date(v.last_read).getTime() >= stamp;
    });
  };

  useEffect(() => {
    if (!channel) return;
    setSeen(computeSeen(channel));
    const onRead = () => setSeen(computeSeen(channel));
    const onNew = () => setSeen(computeSeen(channel));
    channel.on("message.read", onRead);
    channel.on("message.new", onNew);
    const interval = setInterval(() => setSeen(computeSeen(channel)), 3000);
    return () => {
      channel.off("message.read", onRead);
      channel.off("message.new", onNew);
      clearInterval(interval);
    };
  }, [channel]);

  if (!seen) return null;

  return (
    <div className="flex justify-end items-center gap-1 px-4 pb-1 text-xs opacity-80 check-pop">
      <CheckCheckIcon className="size-4 text-sky-500 check-pulse" />
      Seen
    </div>
  );
};

export default ReadStatusBar;
