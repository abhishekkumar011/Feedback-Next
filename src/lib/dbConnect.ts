import mongoose from "mongoose";

type connectionObject = {
  isConnected?: number;
};

const conncetion: connectionObject = {};

async function dbConnect(): Promise<void> {
  if (conncetion.isConnected) {
    console.log("Database is already connected");
    return;
  }

  try {
    const db = await mongoose.connect(process.env.MONGODB_URI || "");

    conncetion.isConnected = db.connections[0].readyState;

    console.log("Database connected successfully");
  } catch (error) {
    console.error("Database connection failed", error);
    process.exit(1);
  }
}

export default dbConnect;