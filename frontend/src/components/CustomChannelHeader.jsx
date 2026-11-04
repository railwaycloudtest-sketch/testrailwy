import { useChannelStateContext } from "stream-chat-react";
import { formatLastSeen, generateAvatar } from "../lib/utils";
import { UsersIcon } from "lucide-react";

const CustomChannelHeader = ({
  friend,
  userId,
  isGroup,
  onlineUserIds,
  onlineUsersMap,
}) => {
  const { channel } = useChannelStateContext();
  const myId = channel?.getClient().user?.id;
  const members = channel
    ? Object.values(channel.state.members).filter((m) => m.user_id)
    : [];
  const groupMode =
    isGroup || members.length > 2 || Boolean(channel?.data?.is_group) || Boolean(channel?.data?.name);

  let displayName = "";
  let avatar = "";
  let subtitleText = "";

  if (groupMode) {
    displayName = channel?.data?.name || "Group";
    avatar = channel?.data?.image || generateAvatar(displayName, displayName.length * 13 + 7);
    const description = channel?.data?.description?.trim();
    subtitleText = description || `${members.length} participants`;
  } else {
    const targetId = friend?._id || userId;
    const otherMember = members.find((m) => m.user_id !== myId);
    displayName =
      friend?.fullName ||
      otherMember?.user?.name ||
      otherMember?.user_id ||
      "";
    avatar = friend?.profilePic || otherMember?.user?.image || "";
    if (!avatar && displayName) {
      avatar = generateAvatar(displayName, displayName.length + 3);
    }

    const whoId = friend?._id || otherMember?.user_id || userId;
    const isOnline = whoId ? onlineUserIds.has(whoId) : false;
    const lastSeen = whoId ? onlineUsersMap.get(whoId) : null;

    subtitleText = isOnline
      ? "Online"
      : formatLastSeen(friend?.lastSeen || lastSeen);
  }

  return (
    <div className="flex items-center gap-3 p-3 border-b border-base-300 bg-base-100">
      <div className="avatar">
        <div className="w-10 rounded-full">
          {avatar ? (
            <img src={avatar} alt={displayName} />
          ) : (
            <div className="bg-base-300 w-full h-full rounded-full flex items-center justify-center">
              <UsersIcon className="size-4 opacity-40" />
            </div>
          )}
        </div>
      </div>
      <div>
        <p className="font-semibold">{displayName}</p>
        {groupMode ? (
          <p className="text-xs opacity-60 truncate max-w-[60vw] sm:max-w-xs">{subtitleText}</p>
        ) : (
          <p className="text-xs flex items-center gap-1">
            <span
              className={`size-2 rounded-full inline-block ${
                subtitleText === "Online" ? "bg-green-500" : "bg-gray-400"
              }`}
            />
            {subtitleText}
          </p>
        )}
      </div>
    </div>
  );
};

export default CustomChannelHeader;
