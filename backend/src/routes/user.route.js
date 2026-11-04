import express from "express";
import { protectRoute } from "../middleware/auth.middleware.js";
import { upload } from "../lib/upload.js";
import {
  acceptFriendRequest,
  addGroupMembers,
  createGroup,
  deleteChat,
  deleteGroup,
  ensureGroupAdmin,
  getFriendRequests,
  getMyFriends,
  getOnlineUsers,
  getOutgoingFriendReqs,
  getRecommendedUsers,
  getUnreadNotifications,
  getUserPublicKeys,
  heartbeat,
  markNotificationsViewed,
  removeGroupMember,
  sendFriendRequest,
  setGroupAdmin,
  updateGroup,
  uploadGroupImage,
} from "../controllers/user.controller.js";

const router = express.Router();

// apply auth middleware to all routes
router.use(protectRoute);

router.get("/", getRecommendedUsers);
router.get("/friends", getMyFriends);
router.get("/:userId/public-keys", getUserPublicKeys);

router.post("/friend-request/:id", sendFriendRequest);
router.put("/friend-request/:id/accept", acceptFriendRequest);

router.get("/friend-requests", getFriendRequests);
router.get("/outgoing-friend-requests", getOutgoingFriendReqs);

router.post("/heartbeat", heartbeat);
router.get("/online-users", getOnlineUsers);

router.get("/unread-notifications", getUnreadNotifications);
router.post("/notifications-viewed", markNotificationsViewed);

router.post("/groups", createGroup);
router.put("/groups/:groupId", updateGroup);
router.post(
  "/groups/:groupId/image",
  ensureGroupAdmin,
  (req, res, next) => {
    upload.single("image")(req, res, (err) => {
      if (err) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({ message: "File too large. Max 5MB" });
        }
        return res.status(400).json({ message: err.message || "Upload failed" });
      }
      next();
    });
  },
  uploadGroupImage
);
router.post("/groups/:groupId/members", addGroupMembers);
router.delete("/groups/:groupId/members/:userId", removeGroupMember);
router.post("/groups/:groupId/admins", setGroupAdmin);
router.delete("/groups/:groupId", deleteGroup);

router.delete("/chats/:channelId", deleteChat);

export default router;
