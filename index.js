require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { ObjectId } = require("mongodb");

const { MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");
const port = process.env.PORT || 3000;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
// middleware
app.use(cors());
app.use(express.json());

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];

  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;

    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    const db = client.db("cook-db");
    const userColl = db.collection("users");
    const mealsColl = db.collection("meals");
    const reviewsCollection = db.collection("reviews");

    // CREATE USER (PROTECTED)
    app.post("/users", verifyJWT, async (req, res) => {
      const user = req.body;

      // 1️⃣ Email in token must match email in request body
      if (req.tokenEmail !== user.email) {
        return res.status(403).send({ message: "Forbidden!" });
      }

      // 2️⃣ Check duplicate user by email
      const exists = await userColl.findOne({ email: user.email });
      if (exists) {
        return res.send({ message: "User already exists" });
      }

      // 3️⃣ Save new user
      const result = await userColl.insertOne(user);
      res.send(result);
    });

    // see all user from db
    app.get("/users", async (req, res) => {
      const result = await userColl.find().toArray();
      res.send(result);
    });

    // CREATE MEAL (PROTECTED)
    app.post("/meals", verifyJWT, async (req, res) => {
      const meal = req.body;

      try {
        // 1️⃣ Only allow the logged-in user's email
        if (meal.userEmail !== req.tokenEmail) {
          return res.status(403).send({ message: "Forbidden!" });
        }

        // 2️⃣ Add createdAt if not provided
        meal.createdAt = meal.createdAt ? new Date(meal.createdAt) : new Date();

        // 3️⃣ Insert meal to DB
        const result = await mealsColl.insertOne(meal);

        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Failed to add meal", error: err });
      }
    });

    // GET ALL MEALS (PUBLIC)
    app.get("/meals", async (req, res) => {
      try {
        const meals = await mealsColl.find().toArray();
        res.send(meals);
      } catch (err) {
        res.status(500).send({ message: "Failed to fetch meals", error: err });
      }
    });

    // GET SINGLE MEAL (PUBLIC)
    app.get("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const meal = await mealsColl.findOne({ _id: new ObjectId(id) });

      if (!meal) {
        return res.status(404).send({ message: "Meal not found" });
      }

      res.send(meal);
    });

    // get all review
    app.get("/reviews", async (req, res) => {
      const result = await reviewsCollection.find().toArray();
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
