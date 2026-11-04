import { StreamChat } from "stream-chat";
import "dotenv/config";

const apiKey = process.env.STEAM_API_KEY;
const apiSecret = process.env.STEAM_API_SECRET;

if (!apiKey || !apiSecret) {
  console.error("Stream API key or Secret is missing");
}

const streamClient = StreamChat.getInstance(apiKey, apiSecret, {
  axiosRequestConfig: { timeout: 20000 },
});

export const createStreamGroup = async ({ groupId, name, members, creatorId }) => {
  const channel = streamClient.channel("messaging", groupId, {
    name,
    members,
    created_by_id: creatorId,
    is_group: true,
    owner: creatorId,
    admins: [],
    group_muted: false,
    image: "",
    description: "",
  });
  await channel.create();
  return { id: groupId };
};

export const getStreamGroupChannel = async (groupId) => {
  const channel = streamClient.channel("messaging", groupId);
  try {
    await channel.query();
  } catch {
    return null;
  }
  return channel;
};

export { streamClient };

export const upsertStreamUser = async (userData) => {
  try {
    await streamClient.upsertUsers([userData]);
    return userData;
  } catch (error) {
    console.error("Error upserting Stream user:", error);
  }
};

export const generateStreamToken = (userId) => {
  try {
    // ensure userId is a string
    const userIdStr = userId.toString();
    return streamClient.createToken(userIdStr);
  } catch (error) {
    console.error("Error generating Stream token:", error);
  }
};
