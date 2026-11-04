import User from "../models/User.js";
import FriendRequest from "../models/FriendRequest.js";
import { createStreamGroup, getStreamGroupChannel, streamClient } from "../lib/stream.js";
import { saveEncryptedUpload } from "../lib/upload.js";

export async function getRecommendedUsers(req, res) {
  try {
    const currentUserId = req.user.id;
    const currentUser = req.user;

    const recommendedUsers = await User.find({
      $and: [
        { _id: { $ne: currentUserId } }, //exclude current user
        { _id: { $nin: currentUser.friends } }, // exclude current user's friends
        { isOnboarded: true },
      ],
    });

    // strip secrets/encrypted-at-rest blobs; deliver only public profile data
    res.status(200).json(recommendedUsers.map(toPublicUser));
  } catch (error) {
    console.error("Error in getRecommendedUsers controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/** Public projection of another user (no secrets, no encrypted blobs). */
export function toPublicUser(doc) {
  const obj = doc?.toObject ? doc.toObject() : doc;
  return {
    _id: obj._id?.toString?.() ?? obj._id,
    fullName: obj.fullName,
    profilePic: obj.profilePic,
    nativeLanguage: obj.nativeLanguage,
    learningLanguage: obj.learningLanguage,
    isOnline: obj.isOnline,
    lastSeen: obj.lastSeen,
    isOnboarded: obj.isOnboarded,
    publicKeys: obj.publicKeys,
    createdAt: obj.createdAt,
  };
}

export async function getMyFriends(req, res) {
  try {
    const user = await User.findById(req.user.id)
      .select("friends")
      .populate("friends", "fullName profilePic nativeLanguage learningLanguage isOnline lastSeen");

    res.status(200).json(user.friends);
  } catch (error) {
    console.error("Error in getMyFriends controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function sendFriendRequest(req, res) {
  try {
    const myId = req.user.id;
    const { id: recipientId } = req.params;

    // prevent sending req to yourself
    if (myId === recipientId) {
      return res.status(400).json({ message: "You can't send friend request to yourself" });
    }

    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ message: "Recipient not found" });
    }

    // check if user is already friends
    if (recipient.friends.includes(myId)) {
      return res.status(400).json({ message: "You are already friends with this user" });
    }

    // check if a req already exists
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { sender: myId, recipient: recipientId },
        { sender: recipientId, recipient: myId },
      ],
    });

    if (existingRequest) {
      return res
        .status(400)
        .json({ message: "A friend request already exists between you and this user" });
    }

    const friendRequest = await FriendRequest.create({
      sender: myId,
      recipient: recipientId,
    });

    res.status(201).json(friendRequest);
  } catch (error) {
    console.error("Error in sendFriendRequest controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function acceptFriendRequest(req, res) {
  try {
    const { id: requestId } = req.params;

    const friendRequest = await FriendRequest.findById(requestId);

    if (!friendRequest) {
      return res.status(404).json({ message: "Friend request not found" });
    }

    // Verify the current user is the recipient
    if (friendRequest.recipient.toString() !== req.user.id) {
      return res.status(403).json({ message: "You are not authorized to accept this request" });
    }

    friendRequest.status = "accepted";
    await friendRequest.save();

    // add each user to the other's friends array
    // $addToSet: adds elements to an array only if they do not already exist.
    await User.findByIdAndUpdate(friendRequest.sender, {
      $addToSet: { friends: friendRequest.recipient },
    });

    await User.findByIdAndUpdate(friendRequest.recipient, {
      $addToSet: { friends: friendRequest.sender },
    });

    res.status(200).json({ message: "Friend request accepted" });
  } catch (error) {
    console.log("Error in acceptFriendRequest controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function getFriendRequests(req, res) {
  try {
    const incomingReqs = await FriendRequest.find({
      recipient: req.user.id,
      status: "pending",
    }).populate("sender", "fullName profilePic nativeLanguage learningLanguage");

    const acceptedReqs = await FriendRequest.find({
      sender: req.user.id,
      status: "accepted",
    }).populate("recipient", "fullName profilePic");

    res.status(200).json({ incomingReqs, acceptedReqs });
  } catch (error) {
    console.log("Error in getPendingFriendRequests controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function getOutgoingFriendReqs(req, res) {
  try {
    const outgoingRequests = await FriendRequest.find({
      sender: req.user.id,
      status: "pending",
    }).populate("recipient", "fullName profilePic nativeLanguage learningLanguage");

    res.status(200).json(outgoingRequests);
  } catch (error) {
    console.log("Error in getOutgoingFriendReqs controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function heartbeat(req, res) {
  try {
    req.user.isOnline = true;
    req.user.lastSeen = new Date();
    await req.user.save();
    res.status(200).json({ success: true });
  } catch (error) {
    console.log("Error in heartbeat controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function getOnlineUsers(req, res) {
  try {
    const cutoff = new Date(Date.now() - 45 * 1000);
    await User.updateMany(
      { isOnline: true, lastSeen: { $lt: cutoff } },
      { isOnline: false }
    );
    const onlineUsers = await User.find({ isOnline: true }).select("_id lastSeen");
    res.status(200).json(onlineUsers.map((u) => ({ _id: u._id.toString(), lastSeen: u.lastSeen })));
  } catch (error) {
    console.log("Error in getOnlineUsers controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function getUnreadNotifications(req, res) {
  try {
    const viewed = req.user.notificationsViewedAt || new Date(0);
    const userId = req.user._id;

    const [incoming, accepted] = await Promise.all([
      FriendRequest.countDocuments({
        recipient: userId,
        status: "pending",
        createdAt: { $gt: viewed },
      }),
      FriendRequest.countDocuments({
        sender: userId,
        status: "accepted",
        updatedAt: { $gt: viewed },
      }),
    ]);

    if (!res.headersSent) {
      return res.status(200).json(incoming + accepted);
    }
  } catch (error) {
    console.log("Error in getUnreadNotifications controller:", error.message);
    if (!res.headersSent) {
      return res.status(500).json({ message: "Internal Server Error" });
    }
  }
}

export async function markNotificationsViewed(req, res) {
  try {
    req.user.notificationsViewedAt = new Date();
    await req.user.save();
    res.status(200).json({ success: true });
  } catch (error) {
    console.log("Error in markNotificationsViewed controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function createGroup(req, res) {
  try {
    const { name, memberIds } = req.body;
    const me = req.user;

    if (!name || !name.trim() || !Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ message: "Group name and at least one member are required" });
    }

    const myFriends = (me.friends || []).map((f) => f.toString());
    const invalid = memberIds.filter((id) => !myFriends.includes(id));
    if (invalid.length > 0) {
      return res.status(400).json({ message: "All group members must be your friends" });
    }

    const members = [...new Set([me._id.toString(), ...memberIds])];
    const groupId = `group-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    try {
      await createStreamGroup({
        groupId,
        name: name.trim(),
        members,
        creatorId: me._id.toString(),
      });
    } catch (streamError) {
      console.error("Error creating Stream group:", streamError.message);
      return res.status(500).json({ message: "Failed to create group" });
    }

    res.status(201).json({ success: true, groupId, name: name.trim(), members });
  } catch (error) {
    console.error("Error in createGroup controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

function getGroupRoles(channel) {
  const owner =
    channel.data?.owner ||
    channel.data?.created_by_id ||
    channel.data?.created_by?.id ||
    null;
  const admins = Array.isArray(channel.data?.admins) ? channel.data.admins : [];
  return { owner, admins };
}

function buildGroupData(channel, overrides = {}) {
  return {
    is_group: true,
    name: channel.data?.name || "",
    owner:
      channel.data?.owner ||
      channel.data?.created_by_id ||
      channel.data?.created_by?.id,
    admins: Array.isArray(channel.data?.admins) ? channel.data.admins : [],
    group_muted: Boolean(channel.data?.group_muted || channel.data?.muted),
    image: channel.data?.image || "",
    description: channel.data?.description || "",
    ...overrides,
  };
}

export async function updateGroup(req, res) {
  try {
    const { groupId } = req.params;
    const { name, muted, description, image } = req.body;
    const me = req.user._id.toString();

    const channel = await getStreamGroupChannel(groupId);
    if (!channel) return res.status(404).json({ message: "Group not found" });
    if (!channel.data?.is_group && !channel.data?.name) {
      return res.status(400).json({ message: "This is not a group" });
    }

    const { owner, admins } = getGroupRoles(channel);
    const isOwner = me === owner;
    const isAdmin = isOwner || admins.includes(me);
    if (!isAdmin) return res.status(403).json({ message: "Only owner or admins can do this" });
    if (!channel.state?.members?.[me]) {
      return res.status(403).json({ message: "You are not a member of this group" });
    }

    const update = {};
    if (typeof name === "string" && name.trim()) update.name = name.trim();
    if (typeof muted === "boolean") update.group_muted = muted;
    if (typeof description === "string") update.description = description.trim().slice(0, 500);
    if (typeof image === "string") update.image = image;
    if (Object.keys(update).length === 0) {
      return res.status(400).json({ message: "Nothing to update" });
    }

    await channel.update(buildGroupData(channel, update));
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error in updateGroup controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function ensureGroupAdmin(req, res, next) {
  try {
    const { groupId } = req.params;
    const me = req.user._id.toString();

    const channel = await getStreamGroupChannel(groupId);
    if (!channel) return res.status(404).json({ message: "Group not found" });

    const { owner, admins } = getGroupRoles(channel);
    if (me !== owner && !admins.includes(me)) {
      return res.status(403).json({ message: "Only owner or admins can change the group photo" });
    }

    req.groupChannel = channel;
    next();
  } catch (error) {
    console.error("Error in ensureGroupAdmin", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function uploadGroupImage(req, res) {
  try {
    const groupId = req.params.groupId;
    const me = req.user._id.toString();

    const channel = req.groupChannel || (await getStreamGroupChannel(groupId));
    if (!channel) return res.status(404).json({ message: "Group not found" });

    const { owner, admins } = getGroupRoles(channel);
    if (me !== owner && !admins.includes(me)) {
      return res.status(403).json({ message: "Only owner or admins can change the group photo" });
    }
    if (!req.file) return res.status(400).json({ message: "No image uploaded" });

    // AES-256-GCM encrypted at rest, decrypted on the fly by /uploads/:name
    const url = `${req.protocol}://${req.get("host")}/uploads/${saveEncryptedUpload(req.file)}`;
    await channel.update(buildGroupData(channel, { image: url }));

    res.status(200).json({ success: true, url });
  } catch (error) {
    console.error("Error in uploadGroupImage controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function addGroupMembers(req, res) {
  try {
    const { groupId } = req.params;
    const { memberIds } = req.body;
    const me = req.user._id.toString();

    if (!Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ message: "Select at least one member" });
    }

    const channel = await getStreamGroupChannel(groupId);
    if (!channel) return res.status(404).json({ message: "Group not found" });

    const { owner, admins } = getGroupRoles(channel);
    const isOwner = me === owner;
    const isAdmin = isOwner || admins.includes(me);
    if (!isAdmin) return res.status(403).json({ message: "Only owner or admins can add members" });

    const myFriends = (req.user.friends || []).map((f) => f.toString());
    const invalid = memberIds.filter((id) => !myFriends.includes(id));
    if (invalid.length > 0) {
      return res.status(400).json({ message: "You can only add your friends" });
    }

    const newIds = memberIds.filter((id) => !channel.state?.members?.[id]);
    if (newIds.length === 0) {
      return res.status(400).json({ message: "These users are already members" });
    }

    await channel.addMembers(newIds);
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error in addGroupMembers controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function removeGroupMember(req, res) {
  try {
    const { groupId, userId } = req.params;
    const me = req.user._id.toString();

    const channel = await getStreamGroupChannel(groupId);
    if (!channel) return res.status(404).json({ message: "Group not found" });

    const { owner, admins } = getGroupRoles(channel);
    const isOwner = me === owner;
    const isAdmin = isOwner || admins.includes(me);
    if (!isAdmin) return res.status(403).json({ message: "Only owner or admins can remove members" });
    if (userId === owner) return res.status(400).json({ message: "The owner cannot be removed" });
    if (!channel.state?.members?.[userId]) {
      return res.status(404).json({ message: "User is not a member" });
    }
    if (admins.includes(userId) && !isOwner) {
      return res.status(403).json({ message: "Only the owner can remove admins" });
    }

    await channel.removeMembers([userId]);

    if (admins.includes(userId)) {
      await channel.update(
        buildGroupData(channel, { admins: admins.filter((id) => id !== userId) })
      );
    }

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error in removeGroupMember controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function setGroupAdmin(req, res) {
  try {
    const { groupId } = req.params;
    const { userId, action } = req.body;
    const me = req.user._id.toString();

    if (!userId || !["promote", "demote"].includes(action)) {
      return res.status(400).json({ message: "A user and a valid action are required" });
    }

    const channel = await getStreamGroupChannel(groupId);
    if (!channel) return res.status(404).json({ message: "Group not found" });

    const { owner, admins } = getGroupRoles(channel);
    if (me !== owner) {
      return res.status(403).json({ message: "Only the owner can manage admins" });
    }
    if (userId === owner) {
      return res.status(400).json({ message: "The owner is always an admin" });
    }
    if (!channel.state?.members?.[userId]) {
      return res.status(404).json({ message: "User is not a member" });
    }

    const nextAdmins = new Set(admins);
    if (action === "promote") nextAdmins.add(userId);
    else nextAdmins.delete(userId);

    await channel.update(buildGroupData(channel, { admins: [...nextAdmins] }));
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error in setGroupAdmin controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function deleteGroup(req, res) {
  try {
    const { groupId } = req.params;
    const me = req.user._id.toString();

    const channel = await getStreamGroupChannel(groupId);
    if (!channel) return res.status(404).json({ message: "Group not found" });
    if (!channel.data?.is_group && !channel.data?.name) {
      return res.status(400).json({ message: "This is not a group" });
    }

    const { owner, admins } = getGroupRoles(channel);
    if (me !== owner && !admins.includes(me)) {
      return res.status(403).json({ message: "Only owner or admins can delete this group" });
    }

    await channel.delete();
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error in deleteGroup controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

export async function deleteChat(req, res) {
  try {
    const { channelId } = req.params;
    const me = req.user._id.toString();

    const channel = streamClient.channel("messaging", channelId);
    try {
      await channel.query();
    } catch {
      return res.status(404).json({ message: "Chat not found" });
    }

    const isMember = Boolean(channel.state?.members?.[me]);
    if (!isMember) return res.status(403).json({ message: "You are not part of this chat" });
    if (channel.data?.is_group || channel.data?.name) {
      return res.status(400).json({ message: "Use the group endpoint to delete groups" });
    }

    await channel.truncate();
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error in deleteChat controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/**
 * GET /api/users/:userId/public-keys
 * Publishes the E2EE public keys (RSA-OAEP + RSA-PSS) of a user so other
 * members can wrap conversation keys / verify message signatures.
 */
export async function getUserPublicKeys(req, res) {
  try {
    const user = await User.findById(req.params.userId)
      .select("publicKeys")
      .lean();

    if (!user?.publicKeys?.rsaEncPub) {
      return res
        .status(404)
        .json({ message: "E2EE keys are not published for this user yet" });
    }

    res.status(200).json({ success: true, publicKeys: user.publicKeys });
  } catch (error) {
    console.error("Error in getUserPublicKeys controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}
