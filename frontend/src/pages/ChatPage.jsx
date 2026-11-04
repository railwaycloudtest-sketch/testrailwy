import { useEffect, useState } from "react";
import { useParams } from "react-router";
import useAuthUser from "../hooks/useAuthUser";
import useOnlineStatus from "../hooks/useOnlineStatus";
import { useQuery } from "@tanstack/react-query";
import { getStreamToken } from "../lib/api";

import {
  Channel,
  Chat,
  MessageInput,
  MessageList,
  Thread,
  Window,
} from "stream-chat-react";
import { StreamChat } from "stream-chat";
import toast from "react-hot-toast";

import ChatLoader from "../components/ChatLoader";
import CallButton from "../components/CallButton";
import CustomChannelHeader from "../components/CustomChannelHeader";
import ReadStatusBar from "../components/ReadStatusBar";
import {
  installMessagingCrypto,
  ensureChannelReady,
  publishMediaKeys,
} from "../lib/crypto/chatCrypto";
import {
  installMediaSecurity,
  ensureCallKey,
  attachCallKeyToWorker,
  setActiveCallId,
} from "../lib/crypto/media";

const STREAM_API_KEY = import.meta.env.VITE_STREAM_API_KEY;

// E2EE media security hooks into every WebRTC peer connection from the start
installMediaSecurity();

const ChatPage = () => {
  const { id: targetUserId } = useParams();

  const [chatClient, setChatClient] = useState(null);
  const [channel, setChannel] = useState(null);
  const [loading, setLoading] = useState(true);

  const { authUser } = useAuthUser();
  const { onlineUserIds, onlineUsersMap } = useOnlineStatus();

  const { data: tokenData } = useQuery({
    queryKey: ["streamToken"],
    queryFn: getStreamToken,
    enabled: !!authUser,
    staleTime: Infinity,
  });

  useEffect(() => {
    const initChat = async () => {
      if (!tokenData?.token || !authUser || !targetUserId) return;

      const client = StreamChat.getInstance(STREAM_API_KEY);
      // E2EE engine: patches the funnel seams once per client (idempotent)
      installMessagingCrypto(client);
      setChatClient(client);

      try {
        if (client.user?.id !== authUser._id) {
          if (client.user) {
            await client.disconnectUser();
          }
          await client.connectUser(
            {
              id: authUser._id,
              name: authUser.fullName,
              image: authUser.profilePic,
            },
            tokenData.token
          );
        }

        const channelId = [authUser._id, targetUserId].sort().join("-");

        const currChannel = client.channel("messaging", channelId, {
          members: [authUser._id, targetUserId],
        });

        if (currChannel.initialized) {
          currChannel.markRead().catch(() => {});
          setChannel(currChannel);
          setLoading(false);
          return;
        }

        await currChannel.watch();
        currChannel.markRead().catch(() => {});

        // provision the SM-1 conversation key (adopt newest keyslide or create)
        await ensureChannelReady(currChannel);

        setChannel(currChannel);
      } catch (error) {
        console.error("Error initializing chat:", error);
        toast.error("Could not connect to chat. Please try again.");
      } finally {
        setLoading(false);
      }
    };

    initChat();
  }, [tokenData?.token, authUser, targetUserId]);

  const handleVideoCall = async () => {
    if (!channel) return;
    try {
      const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
      const callId = `${channel.id}-${suffix}`;
      const callUrl = `${window.location.origin}/call/${callId}`;

      // Per-call media session key, exchanged INSIDE the E2EE chat channel —
      // it never travels to any server in plaintext.
      const mediaKey = ensureCallKey(callId);
      setActiveCallId(callId);
      await attachCallKeyToWorker(callId).catch(() => {});
      await publishMediaKeys(channel, { [callId]: mediaKey }).catch(() => {});

      await channel.sendMessage({
        text: `I've started a video call. Join me here: ${callUrl}`,
      });

      toast.success("Video call link sent successfully!");
    } catch (error) {
      console.error("Could not start encrypted call:", error);
      toast.error("Could not start the call. Please try again.");
    }
  };

  if (loading || !chatClient || !channel) return <ChatLoader />;

  return (
    <div className="h-full chat-fit min-h-0">
      <div className="h-full w-full relative">
        <Chat client={chatClient}>
          <Channel channel={channel}>
            <div className="h-full w-full relative">
              <CallButton handleVideoCall={handleVideoCall} />
              <Window>
                <CustomChannelHeader userId={targetUserId} onlineUserIds={onlineUserIds} onlineUsersMap={onlineUsersMap} />
                <MessageList />
                <ReadStatusBar />
                <MessageInput focus />
              </Window>
            </div>
            <Thread />
          </Channel>
        </Chat>
      </div>
    </div>
  );
};
export default ChatPage;
