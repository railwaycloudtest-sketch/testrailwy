import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    try {
      const usersCol = conn.connection.db.collection("users");
      const indexes = await usersCol.indexes();
      if (indexes.some((i) => i.name === "email_1")) {
        await usersCol.dropIndex("email_1");
        console.log("[db] Dropped legacy email_1 index");
      }
    } catch {
      /* ignore index cleanup */
    }
  } catch (error) {
    console.log("Error in connecting to MongoDB", error);
    process.exit(1); // 1 means failure
  }
};
