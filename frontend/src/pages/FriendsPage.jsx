import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getUserFriends, getStreamToken, createGroup, deleteChat } from "../lib/api";
import useAuthUser from "../hooks/useAuthUser";
import useOnlineStatus from "../hooks/useOnlineStatus";
import { StreamChat } from "stream-chat";
import {
  Channel,
  Chat,
  MessageInput,
  MessageList,
  Thread,
  Window,
} from "stream-chat-react";
import toast from "react-hot-toast";
import CallButton from "../components/CallButton";
import CustomChannelHeader from "../components/CustomChannelHeader";
import ReadStatusBar from "../components/ReadStatusBar";
import AvatarImage from "../components/AvatarImage";
import GroupInfoModal from "../components/GroupInfoModal";
import ConfirmDialog from "../components/ConfirmDialog";
import { formatLastSeen, formatChatTime, generateAvatar } from "../lib/utils";
import {
  ChevronLeftIcon,
  LockIcon,
  MessageCircleIcon,
  MessageSquareDotIcon,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
  PlusIcon,
  SearchIcon,
  Settings2Icon,
  Trash2Icon,
  UsersIcon,
  XCircleIcon,
} from "lucide-react";

const STREAM_API_KEY = import.meta.env.VITE_STREAM_API_KEY;

const FriendsPage = () => {
  const [selectedChat, setSelectedChat] = useState(null);
  const [chatClient, setChatClient] = useState(null);
  const [channel, setChannel] = useState(null);
  const [chats, setChats] = useState([]);
  const [category, setCategory] = useState("chats");
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [listOpen, setListOpen] = useState(() => {
    try {
      return localStorage.getItem("chatListOpen") !== "0";
    } catch {
      return true;
    }
  });
  const [showGroupModal, setShowGroupModal] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupMemberIds, setGroupMemberIds] = useState([]);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [showGroupInfo, setShowGroupInfo] = useState(false);
  const [deleteChatTarget, setDeleteChatTarget] = useState(null);
  const [deletingChat, setDeletingChat] = useState(false);
  const openCidRef = useRef(null);

  const { authUser } = useAuthUser();
  const { onlineUserIds, onlineUsersMap } = useOnlineStatus();

  const { data: friends = [] } = useQuery({
    queryKey: ["friends"],
    queryFn: getUserFriends,
    refetchInterval: 30000,
  });

  const { data: tokenData } = useQuery({
    queryKey: ["streamToken"],
    queryFn: getStreamToken,
    enabled: !!authUser,
    staleTime: Infinity,
  });

  useEffect(() => {
    try {
      localStorage.setItem("chatListOpen", listOpen ? "1" : "0");
    } catch {}
  }, [listOpen]);

  useEffect(() => {
    if (!tokenData?.token || !authUser) return;
    let cancelled = false;
    const initClient = async () => {
      try {
        const client = StreamChat.getInstance(STREAM_API_KEY);
        if (client.user?.id === authUser._id) {
          if (!cancelled) setChatClient(client);
          return;
        }
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
        if (!cancelled) setChatClient(client);
      } catch (error) {
        console.error("Error initializing chat client:", error);
        if (!cancelled) toast.error("Could not connect to chat.");
      }
    };
    initClient();
    return () => {
      cancelled = true;
    };
  }, [tokenData, authUser]);

  const buildChats = useCallback(async () => {
    if (!chatClient || !authUser) return;
    try {
      const channels = await chatClient.queryChannels(
        { type: "messaging", members: { $in: [authUser._id] } },
        [{ last_message_at: -1 }],
        { watch: true, state: true, messages: { limit: 25 } }
      );

      const friendById = new Map(friends.map((f) => [f._id, f]));
      const list = [];
      const linkedFriendIds = new Set();

      channels.forEach((ch) => {
        const members = Object.values(ch.state.members).filter((m) => m.user_id);
        const isGroup =
          Boolean(ch.data?.is_group) || Boolean(ch.data?.name) || members.length > 2;
        const lastMsg = ch.lastMessage();
        let name = "";
        let image = "";
        let otherId = null;
        let lastSeen = null;

        if (isGroup) {
          name = ch.data?.name || "Group";
          image = ch.data?.image || "";
        } else {
          const other = members.find((m) => m.user_id !== authUser._id);
          if (other) {
            otherId = other.user_id;
            linkedFriendIds.add(otherId);
            const f = friendById.get(otherId);
            name = f?.fullName || other.user?.name || otherId;
            image = f?.profilePic || other.user?.image || "";
            lastSeen = f?.lastSeen || null;
          }
        }

        list.push({
          cid: ch.cid,
          id: ch.id,
          name,
          image,
          otherId,
          isGroup,
          lastSeen,
          unread: ch.countUnread(),
          lastText: lastMsg?.text || "",
          lastAt: lastMsg?.created_at || ch.data?.last_message_at || null,
        });
      });

      friends.forEach((f) => {
        if (!linkedFriendIds.has(f._id)) {
          list.push({
            cid: null,
            id: [authUser._id, f._id].sort().join("-"),
            name: f.fullName,
            image: f.profilePic,
            otherId: f._id,
            isGroup: false,
            lastSeen: f.lastSeen || null,
            unread: 0,
            lastText: "",
            lastAt: null,
          });
        }
      });

      list.sort((a, b) => {
        if (!a.lastAt && !b.lastAt) return 0;
        if (!a.lastAt) return 1;
        if (!b.lastAt) return -1;
        return new Date(b.lastAt) - new Date(a.lastAt);
      });

      setChats(list);
    } catch (error) {
      console.error("Error building chats:", error);
    }
  }, [chatClient, friends, authUser]);

  useEffect(() => {
    if (!chatClient) return;
    buildChats();
    const interval = setInterval(buildChats, 5000);
    return () => clearInterval(interval);
  }, [buildChats]);

  useEffect(() => {
    if (!chatClient) return;
    const onNewMessage = (e) => {
      if (e.cid && e.cid === openCidRef.current) {
        chatClient.channel("messaging", e.channel_id).markRead().catch(() => {});
      }
    };
    const listener = chatClient.on("message.new", onNewMessage);
    return () => listener.unsubscribe();
  }, [chatClient]);

  const openChat = async (chat) => {
    setSelectedChat(chat);
    setChannel(null);
    if (!chatClient) return;
    if (chat.cid && chat.cid === openCidRef.current) {
      const existing = chatClient.channel("messaging", chat.id);
      setChannel(existing);
      setChats((prev) => prev.map((c) => (c.cid === chat.cid ? { ...c, unread: 0 } : c)));
      return;
    }
    try {
      const ch = chatClient.channel(
        "messaging",
        chat.id,
        chat.isGroup ? {} : { members: [authUser._id, chat.otherId] }
      );
      await ch.watch();
      ch.markRead().catch(() => {});
      openCidRef.current = ch.cid;
      setChannel(ch);
      setChats((prev) => prev.map((c) => (c.cid === chat.cid ? { ...c, unread: 0 } : c)));
    } catch (error) {
      console.error("Error opening channel:", error);
      toast.error("Could not open chat.");
    }
  };

  const backToList = () => {
    setSelectedChat(null);
    setChannel(null);
    openCidRef.current = null;
  };

  const handleVideoCall = () => {
    if (!channel) return;
    const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const roomId = `${channel.id}-${suffix}`;
    const callUrl = `${window.location.origin}/call/${roomId}`;
    channel.sendMessage({
      text: `I've started a video call. Join me here: ${callUrl}`,
    });
    toast.success("Video call link sent!");
  };

  const handleCreateGroup = async () => {
    if (!groupName.trim() || groupMemberIds.length === 0) {
      toast.error("Group name and at least one member are required");
      return;
    }
    setCreatingGroup(true);
    try {
      await createGroup({ name: groupName.trim(), memberIds: groupMemberIds });
      toast.success("Group created!");
      setShowGroupModal(false);
      setGroupName("");
      setGroupMemberIds([]);
      setCategory("groups");
      setTimeout(buildChats, 800);
    } catch (error) {
      toast.error(error.response?.data?.message || "Failed to create group");
    } finally {
      setCreatingGroup(false);
    }
  };

  const handleDeleteChat = async () => {
    if (!deleteChatTarget) return;
    setDeletingChat(true);
    try {
      await deleteChat(deleteChatTarget.id);
      toast.success("Chat cleared");
      if (selectedChat?.id === deleteChatTarget.id && channel) {
        await channel.watch().catch(() => {});
      }
      setDeleteChatTarget(null);
      await buildChats();
    } catch (error) {
      toast.error(error.response?.data?.message || "Failed to clear chat");
    } finally {
      setDeletingChat(false);
    }
  };

  const handleGroupDeleted = () => {
    setShowGroupInfo(false);
    backToList();
    buildChats();
  };

  const toggleGroupMember = (id) => {
    setGroupMemberIds((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const chatsUnread = chats.filter((c) => !c.isGroup).reduce((s, c) => s + c.unread, 0);
  const groupsUnread = chats.filter((c) => c.isGroup).reduce((s, c) => s + c.unread, 0);
  const totalUnread = chatsUnread + groupsUnread;

  const filteredChats = useMemo(() => {
    let result = chats.filter((c) => (category === "groups" ? c.isGroup : !c.isGroup));
    if (unreadOnly) result = result.filter((c) => c.unread > 0);
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter((c) => c.name.toLowerCase().includes(q));
    }
    return result;
  }, [chats, category, unreadOnly, search]);

  const channelData = channel?.data || {};
  const ownerId =
    channelData.owner || channelData.created_by_id || channelData.created_by?.id;
  const admins = Array.isArray(channelData.admins) ? channelData.admins : [];
  const isOwner = ownerId === authUser?._id;
  const isAdmin = isOwner || admins.includes(authUser?._id);
  const inputLocked =
    Boolean(channelData.group_muted || channelData.muted) && !isAdmin;

  const listPanelClass = selectedChat
    ? listOpen
      ? "hidden md:flex"
      : "hidden"
    : listOpen
    ? "flex"
    : "flex md:hidden";

  const renderChatRow = (chat) => {
    const isOnline = !chat.isGroup && chat.otherId && onlineUserIds.has(chat.otherId);
    const lastSeen =
      (chat.otherId ? onlineUsersMap.get(chat.otherId) : null) || chat.lastSeen || null;
    const avatarSrc =
      chat.image || generateAvatar(chat.name || "Group", chat.name?.length || 3);

    return (
      <button
        key={chat.cid || chat.id}
        onClick={() => openChat(chat)}
        className={`w-full flex items-center gap-3 p-3 hover:bg-base-300/70 transition-colors text-left ${
          selectedChat?.id === chat.id ? "bg-base-300" : ""
        }`}
      >
        <div className="avatar size-12 relative shrink-0">
          <AvatarImage
            src={avatarSrc}
            alt={chat.name}
            name={chat.name}
            className="rounded-full w-full h-full object-cover"
          />
          {!chat.isGroup && (
            <span
              className={`absolute bottom-0 right-0 size-3 rounded-full border-2 border-base-200 ${
                isOnline ? "bg-green-500 online-dot" : "bg-gray-400"
              }`}
            />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <p className="font-semibold truncate">
              {chat.name}
              {chat.isGroup && (
                <span className="text-[10px] ml-1 opacity-50 font-normal">group</span>
              )}
            </p>
            {chat.lastAt && (
              <span
                className={`text-[11px] shrink-0 ${
                  chat.unread > 0 ? "text-primary font-semibold" : "opacity-50"
                }`}
              >
                {formatChatTime(chat.lastAt)}
              </span>
            )}
          </div>
          <div className="flex items-center justify-between gap-2">
            {!chat.isGroup && !chat.lastText ? (
              isOnline ? (
                <span className="text-xs text-green-500">Online</span>
              ) : (
                <span className="text-xs opacity-50 truncate">
                  {formatLastSeen(lastSeen)}
                </span>
              )
            ) : (
              <>
                <p className="text-xs truncate opacity-70">
                  {chat.lastText || (chat.isGroup ? "Say hi to the group" : "")}
                </p>
                {chat.unread > 0 && (
                  <span className="unread-pill shrink-0">
                    {chat.unread > 99 ? "99+" : chat.unread}
                  </span>
                )}
              </>
            )}
          </div>
        </div>
      </button>
    );
  };

  return (
    <div className="flex h-full bg-base-100 min-h-0">
      {/* Collapsed rail - always lets the user reopen the list */}
      {!listOpen && (
        <div className="hidden md:flex flex-col items-center gap-3 w-12 shrink-0 border-r border-base-300 bg-base-100 py-3">
          <button
            className="btn btn-ghost btn-sm btn-circle"
            onClick={() => setListOpen(true)}
            title="Open chats"
            aria-label="Open chats"
          >
            <PanelLeftOpenIcon className="size-5" />
          </button>
          <MessageCircleIcon className="size-4 opacity-40" />
        </div>
      )}

      {/* Chat list panel */}
      <div
        className={`${listPanelClass} flex-col w-full md:w-80 lg:w-96 border-r border-base-300 shrink-0 min-h-0`}
      >
        <div className="p-3 border-b border-base-300 flex items-center justify-between gap-2 shrink-0">
          <h2 className="text-xl font-bold">Chats</h2>
          <div className="flex items-center gap-1">
            <button
              className="btn btn-ghost btn-sm btn-circle hidden md:flex"
              onClick={() => setListOpen(false)}
              title="Close list"
            >
              <PanelLeftCloseIcon className="size-5" />
            </button>
            <button
              className="btn btn-primary btn-sm btn-circle"
              onClick={() => setShowGroupModal(true)}
              title="Create group"
            >
              <PlusIcon className="size-4" />
            </button>
          </div>
        </div>

        <div className="p-2 border-b border-base-300 space-y-2 shrink-0">
          <label className="input input-sm input-bordered flex items-center gap-2 w-full">
            <SearchIcon className="size-4 opacity-50" />
            <input
              type="text"
              placeholder={category === "groups" ? "Search groups..." : "Search chats..."}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="grow bg-transparent focus:outline-none"
            />
            {search && (
              <button onClick={() => setSearch("")}>
                <XCircleIcon className="size-4 opacity-40" />
              </button>
            )}
          </label>

          <div className="flex gap-1 items-center">
            <button
              className={`btn btn-xs flex-1 rounded-full gap-1 ${
                category === "chats" ? "btn-primary" : "btn-ghost"
              }`}
              onClick={() => setCategory("chats")}
            >
              <MessageCircleIcon className="size-3.5" />
              Chats
              {chatsUnread > 0 && (
                <span className="badge badge-xs badge-error text-white rounded-full">
                  {chatsUnread}
                </span>
              )}
            </button>
            <button
              className={`btn btn-xs flex-1 rounded-full gap-1 ${
                category === "groups" ? "btn-primary" : "btn-ghost"
              }`}
              onClick={() => setCategory("groups")}
            >
              <UsersIcon className="size-3.5" />
              Groups
              {groupsUnread > 0 && (
                <span className="badge badge-xs badge-error text-white rounded-full">
                  {groupsUnread}
                </span>
              )}
            </button>
            <button
              className={`btn btn-xs btn-circle relative overflow-visible ${
                unreadOnly ? "btn-warning" : "btn-ghost"
              }`}
              onClick={() => setUnreadOnly((v) => !v)}
              title="Show unread messages only"
            >
              <MessageSquareDotIcon className="size-4" />
              {totalUnread > 0 && (
                <span className="absolute -top-1.5 -right-1.5 min-w-4 h-4 px-1 rounded-full bg-error text-white text-[10px] leading-4 font-bold badge-pop z-10">
                  {totalUnread > 99 ? "99+" : totalUnread}
                </span>
              )}
            </button>
          </div>
        </div>

        <div className="flex-1 basis-0 min-h-0 overflow-y-auto no-scrollbar">
          {friends.length === 0 && chats.length === 0 ? (
            <div className="p-8 text-center opacity-60">
              <MessageCircleIcon className="size-12 mx-auto mb-3" />
              <p>No friends yet</p>
              <p className="text-sm mt-1">Add friends from the Home page to start chatting</p>
            </div>
          ) : filteredChats.length === 0 ? (
            <div className="p-8 text-center opacity-60">
              {unreadOnly ? (
                <p>No unread messages</p>
              ) : category === "groups" ? (
                <div>
                  <UsersIcon className="size-10 mx-auto mb-2 opacity-50" />
                  <p>No groups yet</p>
                  <p className="text-sm mt-1">Press + to create your first group</p>
                </div>
              ) : (
                <p>No chats found</p>
              )}
            </div>
          ) : (
            filteredChats.map(renderChatRow)
          )}
        </div>
      </div>

      {/* Chat panel */}
      <div
        className={`flex-col flex-1 min-w-0 min-h-0 relative ${
          selectedChat ? "flex" : "hidden md:flex"
        }`}
      >
        {selectedChat && (
          <div className="md:hidden border-b border-base-300 flex items-center gap-2 p-2 pr-28 bg-base-100 shrink-0">
            <button className="btn btn-ghost btn-sm btn-circle" onClick={backToList}>
              <ChevronLeftIcon className="size-5" />
            </button>
            <AvatarImage
              src={
                selectedChat.image ||
                generateAvatar(selectedChat.name, selectedChat.name.length + 1)
              }
              alt={selectedChat.name}
              name={selectedChat.name}
              className="size-9 rounded-full object-cover"
            />
            <span className="font-semibold truncate">{selectedChat.name}</span>
          </div>
        )}

        {!selectedChat ? (
          <div className="flex items-center justify-center h-full text-center p-8">
            <div>
              <MessageCircleIcon className="size-16 mx-auto mb-4 opacity-30" />
              <p className="text-xl opacity-60">Select a chat to start messaging</p>
            </div>
          </div>
        ) : !channel || !chatClient ? (
          <div className="flex items-center justify-center h-full">
            <span className="loading loading-spinner loading-lg" />
          </div>
        ) : (
          <>
            <div className="absolute top-0 right-14 p-3 z-20 flex items-center gap-2">
              {selectedChat.isGroup ? (
                <button
                  className="btn btn-sm btn-circle"
                  onClick={() => setShowGroupInfo(true)}
                  title="Group info"
                >
                  <Settings2Icon className="size-4" />
                </button>
              ) : (
                <button
                  className="btn btn-sm btn-circle btn-error"
                  onClick={() => setDeleteChatTarget(selectedChat)}
                  title="Clear chat"
                >
                  <Trash2Icon className="size-4" />
                </button>
              )}
            </div>

            <div className="flex-1 min-h-0 chat-fit">
              <Chat client={chatClient}>
                <Channel channel={channel}>
                  <div className="h-full relative">
                    <CallButton handleVideoCall={handleVideoCall} />
                    <Window>
                      <CustomChannelHeader
                        friend={
                          selectedChat.isGroup
                            ? null
                            : {
                                _id: selectedChat.otherId,
                                fullName: selectedChat.name,
                                profilePic: selectedChat.image,
                                lastSeen: selectedChat.lastSeen,
                              }
                        }
                        isGroup={selectedChat.isGroup}
                        onlineUserIds={onlineUserIds}
                        onlineUsersMap={onlineUsersMap}
                      />
                      <MessageList />
                      {inputLocked && (
                        <div className="flex items-center justify-center gap-2 px-4 py-2 text-xs bg-warning/15 text-warning border-t border-warning/30">
                          <LockIcon className="size-3.5" />
                          Only admins can send messages in this group
                        </div>
                      )}
                      <ReadStatusBar />
                      <MessageInput focus disabled={inputLocked} />
                    </Window>
                  </div>
                  <Thread />
                </Channel>
              </Chat>
            </div>

            <GroupInfoModal
              open={showGroupInfo}
              onClose={() => setShowGroupInfo(false)}
              channel={channel}
              authUser={authUser}
              friends={friends}
              onChanged={async () => {
                setSelectedChat((prev) =>
                  prev ? { ...prev, name: channel?.data?.name || prev.name } : prev
                );
                await buildChats();
              }}
              onDeleted={handleGroupDeleted}
            />
          </>
        )}
      </div>

      <ConfirmDialog
        open={Boolean(deleteChatTarget)}
        title="Clear this chat?"
        message="All messages in this conversation will be permanently deleted for both of you. This cannot be undone."
        confirmLabel="Clear chat"
        loading={deletingChat}
        onCancel={() => setDeleteChatTarget(null)}
        onConfirm={handleDeleteChat}
      />

      {/* Group creation modal */}
      {showGroupModal && (
        <div
          className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
          onClick={() => setShowGroupModal(false)}
        >
          <div
            className="bg-base-100 rounded-2xl w-full max-w-md p-6 shadow-2xl modal-pop max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold">Create group chat</h3>
              <button
                className="btn btn-ghost btn-sm btn-circle"
                onClick={() => setShowGroupModal(false)}
              >
                <XCircleIcon className="size-5" />
              </button>
            </div>

            <input
              type="text"
              placeholder="Group name"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              className="input input-bordered w-full mb-4"
            />

            <p className="text-sm font-semibold mb-2">
              Add friends ({groupMemberIds.length} selected)
            </p>
            <div className="space-y-1 overflow-y-auto no-scrollbar flex-1 min-h-0 border rounded-lg p-2">
              {friends.length === 0 ? (
                <p className="text-sm opacity-60 text-center py-4">
                  Add friends first to create groups
                </p>
              ) : (
                friends.map((f) => (
                  <label
                    key={f._id}
                    className="flex items-center gap-3 p-2 rounded-lg hover:bg-base-200 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      className="checkbox checkbox-primary checkbox-sm"
                      checked={groupMemberIds.includes(f._id)}
                      onChange={() => toggleGroupMember(f._id)}
                    />
                    <div className="avatar size-10">
                      <AvatarImage
                        src={f.profilePic}
                        alt={f.fullName}
                        name={f.fullName}
                        className="rounded-full w-full h-full object-cover"
                      />
                    </div>
                    <span className="font-medium truncate">{f.fullName}</span>
                  </label>
                ))
              )}
            </div>

            <button
              className="btn btn-primary w-full mt-4"
              onClick={handleCreateGroup}
              disabled={creatingGroup || !groupName.trim() || groupMemberIds.length === 0}
            >
              {creatingGroup ? "Creating..." : "Create group"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default FriendsPage;
