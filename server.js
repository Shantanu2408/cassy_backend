const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { CosmosClient } = require("@azure/cosmos");
const config = require("./config");

const app = express();
app.use(express.json());
app.use(cors());

/* ===== COSMOS CONNECTION ===== */
const client = new CosmosClient({
  endpoint: config.endpoint,
  key: config.key
});

const container = client
  .database(config.databaseId)
  .container(config.containerId);

/* ===== REGISTER ===== */
app.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).send("Missing fields");
    }

    const hash = await bcrypt.hash(password, 10);

    const user = {
      id: Date.now().toString(),
      username,
      email,
      passwordHash: hash,
      role,
      status: "approved", // approval required
      createdAt: new Date()
    };

    await container.items.create(user);

    res.send("User registered. Waiting for approval.");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error in register");
  }
});

/* ===== LOGIN ===== */
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const query = {
      query: "SELECT * FROM c WHERE c.email=@u OR c.username=@u",
      parameters: [{ name: "@u", value: username }]
    };

    const { resources } = await container.items.query(query).fetchAll();

    if (resources.length === 0) {
      return res.status(401).send("User not found");
    }

    const user = resources[0];

    if (user.status !== "approved") {
      return res.status(403).send("User not approved yet");
    }

    const match = await bcrypt.compare(password, user.passwordHash);

    if (!match) {
      return res.status(401).send("Invalid password");
    }

    const token = jwt.sign(
      {
        email: user.email,
        role: user.role
      },
      config.jwtSecret,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).send("Login error");
  }
});

/* ===== GET USERS (ADMIN) ===== */
app.get("/users", async (req, res) => {
  try {
    const { resources } = await container.items.readAll().fetchAll();
    res.json(resources);
  } catch (err) {
    res.status(500).send("Error fetching users");
  }
});

/* ===== APPROVE USER ===== */
app.post("/approve/:email", async (req, res) => {
  try {
    const email = req.params.email;

    const query = {
      query: "SELECT * FROM c WHERE c.email=@e",
      parameters: [{ name: "@e", value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();

    if (resources.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = resources[0];
    user.status = "approved";

    await container.item(user.id, user.email).replace(user);

    res.send("User approved");

  } catch (err) {
    console.error(err);
    res.status(500).send("Error approving user");
  }
});

/* ===== HEALTH CHECK ===== */
app.get("/", (req, res) => {
  res.send("CASSY Backend Running");
});

/* ===== START SERVER ===== */
app.listen(3000, () => {
  console.log("🚀 Server running on http://localhost:3000");
});
