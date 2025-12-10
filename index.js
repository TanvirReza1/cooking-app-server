require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { ObjectId, MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");
const port = process.env.PORT || 3000;

// decode firebase service account
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(cors());
app.use(express.json());

// SAFE auth header parsing
const getTokenFromHeader = (req) => {
  const auth = req.headers?.authorization;
  if (!auth) return null;
  const parts = auth.split(" ");
  if (parts.length !== 2) return null;
  return parts[1];
};

// jwt middleware
const verifyJWT = async (req, res, next) => {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decodedToken.email;
    next();
  } catch (err) {
    console.error("verifyJWT error:", err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Mongo client
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // connect once
    await client.connect();

    const db = client.db("cook-db");
    const userColl = db.collection("users");
    const mealsColl = db.collection("meals");
    const reviewsCollection = db.collection("reviews");
    const orderColl = db.collection("orders");
    const favoritesCollection = db.collection("favorites");
    const ordersCollection = db.collection("orders");

    // (Optional) create indexes to speed queries
    // await reviewsCollection.createIndex({ foodId: 1 });
    // await favoritesCollection.createIndex({ userEmail: 1, mealId: 1 }, { unique: false });

    // CREATE USER (PROTECTED)
    app.post("/users", verifyJWT, async (req, res) => {
      try {
        const user = req.body;
        if (!user?.email)
          return res.status(400).send({ message: "email required" });
        if (req.tokenEmail !== user.email)
          return res.status(403).send({ message: "Forbidden!" });

        const exists = await userColl.findOne({ email: user.email });
        if (exists) return res.send({ message: "User already exists" });

        const result = await userColl.insertOne(user);
        res.send(result);
      } catch (err) {
        console.error("/users POST error:", err);
        res.status(500).send({ message: "Server error", error: err });
      }
    });

    // GET all users (public/admin)
    app.get("/users", async (req, res) => {
      try {
        const result = await userColl.find().toArray();
        res.send(result);
      } catch (err) {
        console.error("/users GET error:", err);
        res.status(500).send({ message: "Failed to fetch users", error: err });
      }
    });

    // CREATE MEAL (PROTECTED)
    app.post("/meals", verifyJWT, async (req, res) => {
      try {
        const meal = req.body;
        if (!meal)
          return res.status(400).send({ message: "Meal body required" });

        if (meal.userEmail !== req.tokenEmail)
          return res.status(403).send({ message: "Forbidden!" });

        meal.createdAt = meal.createdAt ? new Date(meal.createdAt) : new Date();

        const result = await mealsColl.insertOne(meal);
        res.send(result);
      } catch (err) {
        console.error("/meals POST error:", err);
        res.status(500).send({ message: "Failed to add meal", error: err });
      }
    });

    // GET ALL MEALS
    app.get("/meals", async (req, res) => {
      try {
        const meals = await mealsColl.find().toArray();
        res.send(meals);
      } catch (err) {
        console.error("/meals GET error:", err);
        res.status(500).send({ message: "Failed to fetch meals", error: err });
      }
    });

    // GET SINGLE MEAL (safe ObjectId check)
    app.get("/meals/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id))
          return res.status(400).send({ message: "Invalid meal id" });

        const meal = await mealsColl.findOne({ _id: new ObjectId(id) });
        if (!meal) return res.status(404).send({ message: "Meal not found" });

        res.send(meal);
      } catch (err) {
        console.error("/meals/:id error:", err);
        res.status(500).send({ message: "Failed to fetch meal", error: err });
      }
    });

    // GET all reviews (public)
    app.get("/reviews", async (req, res) => {
      try {
        const result = await reviewsCollection
          .find()
          .sort({ date: -1 })
          .toArray();
        res.send(result);
      } catch (err) {
        console.error("/reviews GET error:", err);
        res
          .status(500)
          .send({ message: "Failed to fetch reviews", error: err });
      }
    });

    // GET reviews for a specific meal (public)
    // Expect frontend to send mealId as string (e.g. meal._id.toString())
    app.get("/reviews/:mealId", async (req, res) => {
      try {
        const mealId = req.params.mealId;
        const reviews = await reviewsCollection
          .find({ foodId: mealId })
          .sort({ date: -1 })
          .toArray();
        res.send(reviews);
      } catch (err) {
        console.error("/reviews/:mealId error:", err);
        res
          .status(500)
          .send({ message: "Failed to fetch reviews", error: err });
      }
    });

    // ADD REVIEW (Protected)
    app.post("/reviews", verifyJWT, async (req, res) => {
      try {
        const review = req.body;
        if (!review?.foodId)
          return res.status(400).send({ message: "foodId required" });

        // If reviewerEmail provided, ensure it matches token
        if (review.reviewerEmail && review.reviewerEmail !== req.tokenEmail) {
          return res.status(403).send({ message: "Forbidden!" });
        }

        // Normalize: store foodId as string
        review.foodId = String(review.foodId);
        review.date = review.date ? new Date(review.date) : new Date();

        const result = await reviewsCollection.insertOne(review);
        res.send(result);
      } catch (err) {
        console.error("/reviews POST error:", err);
        res
          .status(500)
          .send({ message: "Failed to submit review", error: err });
      }
    });

    // ADD TO FAVORITES (Protected)
    app.post("/favorites", verifyJWT, async (req, res) => {
      try {
        const favorite = req.body;
        if (!favorite?.userEmail || !favorite?.mealId)
          return res
            .status(400)
            .send({ message: "userEmail and mealId required" });

        if (favorite.userEmail !== req.tokenEmail)
          return res.status(403).send({ message: "Forbidden!" });

        // store mealId as string to avoid ObjectId mismatch
        const mealIdStr = String(favorite.mealId);
        const exists = await favoritesCollection.findOne({
          userEmail: favorite.userEmail,
          mealId: mealIdStr,
        });

        if (exists) {
          return res.send({ exists: true });
        }

        favorite.mealId = mealIdStr;
        favorite.addedTime = new Date();

        const result = await favoritesCollection.insertOne(favorite);
        res.send({ success: true, result });
      } catch (err) {
        console.error("/favorites POST error:", err);
        res.status(500).send({ message: "Failed to add favorite", error: err });
      }
    });

    // GET USER'S FAVORITES (Protected)
    // call: GET /favorites?email=user@example.com
    app.get("/favorites", verifyJWT, async (req, res) => {
      try {
        const email = req.query.email;
        if (!email)
          return res.status(400).send({ message: "email query required" });
        if (email !== req.tokenEmail)
          return res.status(403).send({ message: "Forbidden!" });

        const result = await favoritesCollection
          .find({ userEmail: email })
          .toArray();
        res.send(result);
      } catch (err) {
        console.error("/favorites GET error:", err);
        res
          .status(500)
          .send({ message: "Failed to fetch favorites", error: err });
      }
    });

    // CREATE ORDER (Protected)
    app.post("/orders", verifyJWT, async (req, res) => {
      try {
        const order = req.body;
        if (!order?.userEmail)
          return res.status(400).send({ message: "userEmail required" });

        if (order.userEmail !== req.tokenEmail)
          return res.status(403).send({ message: "Forbidden!" });

        order.orderTime = new Date();
        const result = await ordersCollection.insertOne(order);
        res.send(result);
      } catch (err) {
        console.error("/orders POST error:", err);
        res.status(500).send({ message: "Failed to create order", error: err });
      }
    });

    // orders route
    app.post("/orders", async (req, res) => {
      try {
        const order = req.body;
        const result = await orderColl.insertOne(order);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Failed to place order" });
      }
    });

    // Ping to confirm DB connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // keep client open for server lifetime (do not close)
  }
}

run().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
