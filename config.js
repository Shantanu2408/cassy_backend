require("dotenv").config();

module.exports = {
  endpoint: process.env.COSMOS_ENDPOINT,
  key: process.env.COSMOS_KEY,
  databaseId: "UserDB",
  containerId: "Users",
  jwtSecret: process.env.JWT_SECRET
};
