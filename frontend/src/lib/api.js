import { axiosInstance } from "./axios";

export const signup = async (signupData) => {
  const response = await axiosInstance.post("/auth/signup", signupData);
  return response.data;
};

export const login = async (loginData) => {
  const response = await axiosInstance.post("/auth/login", loginData);
  return response.data;
};
export const logout = async () => {
  const response = await axiosInstance.post("/auth/logout");
  return response.data;
};

export const getAuthUser = async () => {
  try {
    const res = await axiosInstance.get("/auth/me");
    return res.data;
  } catch (error) {
    console.log("Error in getAuthUser:", error);
    return null;
  }
};

export const completeOnboarding = async (userData) => {
  const response = await axiosInstance.post("/auth/onboarding", userData);
  return response.data;
};

export async function getUserFriends() {
  const response = await axiosInstance.get("/users/friends");
  return response.data;
}

export async function getRecommendedUsers() {
  const response = await axiosInstance.get("/users");
  return response.data;
}

export async function getOutgoingFriendReqs() {
  const response = await axiosInstance.get("/users/outgoing-friend-requests");
  return response.data;
}

export async function sendFriendRequest(userId) {
  const response = await axiosInstance.post(`/users/friend-request/${userId}`);
  return response.data;
}

export async function getFriendRequests() {
  const response = await axiosInstance.get("/users/friend-requests");
  return response.data;
}

export async function acceptFriendRequest(requestId) {
  const response = await axiosInstance.put(`/users/friend-request/${requestId}/accept`);
  return response.data;
}

export async function getStreamToken() {
  const response = await axiosInstance.get("/chat/token");
  return response.data;
}

export async function updateProfile(userData) {
  const response = await axiosInstance.put("/auth/profile", userData);
  return response.data;
}

export async function uploadProfilePic(file) {
  const formData = new FormData();
  formData.append("profilePic", file);
  const response = await axiosInstance.post("/auth/upload-profile-pic", formData);
  return response.data;
}

export async function sendHeartbeat() {
  const response = await axiosInstance.post("/users/heartbeat");
  return response.data;
}

export async function getOnlineUsers() {
  const response = await axiosInstance.get("/users/online-users");
  return response.data;
}

export async function getUnreadNotifications() {
  const response = await axiosInstance.get("/users/unread-notifications");
  return response.data;
}

export async function markNotificationsViewed() {
  const response = await axiosInstance.post("/users/notifications-viewed");
  return response.data;
}

export async function createGroup({ name, memberIds }) {
  const response = await axiosInstance.post("/users/groups", { name, memberIds });
  return response.data;
}

export async function updateGroup(groupId, data) {
  const response = await axiosInstance.put(`/users/groups/${groupId}`, data);
  return response.data;
}

export async function uploadGroupImage(groupId, file) {
  const formData = new FormData();
  formData.append("image", file);
  const response = await axiosInstance.post(`/users/groups/${groupId}/image`, formData);
  return response.data;
}

export async function addGroupMembers(groupId, memberIds) {
  const response = await axiosInstance.post(`/users/groups/${groupId}/members`, { memberIds });
  return response.data;
}

export async function removeGroupMember(groupId, userId) {
  const response = await axiosInstance.delete(`/users/groups/${groupId}/members/${userId}`);
  return response.data;
}

export async function setGroupAdmin(groupId, userId, action) {
  const response = await axiosInstance.post(`/users/groups/${groupId}/admins`, { userId, action });
  return response.data;
}

export async function deleteGroup(groupId) {
  const response = await axiosInstance.delete(`/users/groups/${groupId}`);
  return response.data;
}

export async function deleteChat(channelId) {
  const response = await axiosInstance.delete(`/users/chats/${channelId}`);
  return response.data;
}

/* -------------------------------------------------------------------------- */
/* E2EE security endpoints                                                     */
/* -------------------------------------------------------------------------- */

export async function getCryptoConfig() {
  const response = await axiosInstance.get("/crypto/config");
  return response.data;
}

export async function getMyCryptoKeys() {
  const response = await axiosInstance.get("/crypto/my-keys");
  return response.data;
}

export async function publishMyCryptoKeys(payload) {
  const response = await axiosInstance.post("/crypto/my-keys", payload);
  return response.data;
}

export async function getUserPublicKeys(userId) {
  const response = await axiosInstance.get(`/users/${userId}/public-keys`);
  return response.data;
}

export async function getTlsFingerprint() {
  const response = await axiosInstance.get("/crypto/cert-fp");
  return response.data;
}
