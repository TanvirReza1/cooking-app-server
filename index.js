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
    const favoritesCollection = db.collection("favorites");
    const ordersCollection = db.collection("orders");
    const roleRequestColl = db.collection("roleRequests");
    const orderRequestsCollection = db.collection("orderRequests");

    // verify admin
    const verifyAdmin = async (req, res, next) => {
      const user = await userColl.findOne({ email: req.tokenEmail });
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "Admin only!" });
      }
      next();
    };

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

    // GET all users (Admin Only)
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await userColl.find().toArray();
      res.send(users);
    });

    // make fraud
    app.patch(
      "/users/make-fraud/:email",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;

        const result = await userColl.updateOne(
          { email },
          { $set: { status: "fraud" } }
        );

        res.send({ success: true, result });
      }
    );

    // CREATE MEAL and fraud chef can't meal (PROTECTED)
    app.post("/meals", verifyJWT, async (req, res) => {
      const user = await userColl.findOne({ email: req.tokenEmail });

      // FRAUD CHEF BLOCK
      if (user.role === "chef" && user.status === "fraud") {
        return res.status(403).send({
          message: "Fraud chefs cannot create meals",
        });
      }

      const meal = req.body;

      meal.createdAt = new Date();

      const result = await mealsColl.insertOne(meal);
      res.send(result);
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
    app.get("/favorites/:email", async (req, res) => {
      const result = await favoritesCollection
        .find({ userEmail: req.params.email })
        .toArray();
      res.send(result);
    });

    app.delete("/favorites/:id", async (req, res) => {
      const result = await favoritesCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    // BLOCK FRAUD USERS to post orders ( (Protected)
    app.post("/orders", verifyJWT, async (req, res) => {
      const user = await userColl.findOne({ email: req.tokenEmail });

      // FRAUD CUSTOMER BLOCK
      if (user.status === "fraud" && user.role === "user") {
        return res.status(403).send({
          message: "Fraud users cannot place orders",
        });
      }

      const order = req.body;
      order.orderTime = new Date();

      const result = await ordersCollection.insertOne(order);
      res.send(result);
    });

    // GET ORDERS BY USER EMAIL
    app.get("/orders", async (req, res) => {
      try {
        const email = req.query.email;
        if (!email) {
          return res.status(400).send({ message: "Email query required" });
        }

        const orders = await ordersCollection
          .find({ userEmail: email })
          .toArray();
        res.send(orders);
      } catch (err) {
        console.error("/orders GET error:", err);
        res.status(500).send({ message: "Failed to fetch orders" });
      }
    });

    // GET user by email (Protected)
    app.get("/users/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;

        // Security: only allow user to read their own data
        if (email !== req.tokenEmail) {
          return res.status(403).send({ message: "Forbidden!" });
        }

        const user = await userColl.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send(user);
      } catch (err) {
        console.error("/users/:email GET error:", err);
        res.status(500).send({ message: "Failed to fetch user", error: err });
      }
    });

    // CREATE ROLE REQUEST (Protected)
    app.post("/role-requests", verifyJWT, async (req, res) => {
      try {
        const body = req.body;
        delete body._id;

        if (!body.userEmail || !body.requestType) {
          return res.status(400).send({ message: "Missing fields" });
        }

        if (body.userEmail !== req.tokenEmail) {
          return res.status(403).send({ message: "Forbidden!" });
        }

        body.requestTime = new Date();
        body.requestStatus = "pending";

        const result = await roleRequestColl.insertOne(body);
        res.send({ success: true, result });
      } catch (err) {
        if (err.code === 11000) {
          return res.status(409).send({
            success: false,
            message:
              "You already submitted a request. Please wait for admin approval.",
          });
        }

        console.error("/role-requests POST error:", err);
        res.status(500).send({ message: "Failed to create role request" });
      }
    });

    // GET ALL ROLE REQUESTS — (Admin only)
    app.get("/role-requests", verifyJWT, async (req, res) => {
      try {
        const requests = await roleRequestColl.find().toArray();
        res.send(requests);
      } catch (err) {
        console.error("/role-requests GET error:", err);
        res
          .status(500)
          .send({ message: "Failed to fetch role requests", error: err });
      }
    });

    // GET reviews of logged-in user
    app.get("/user-reviews", verifyJWT, async (req, res) => {
      try {
        const email = req.query.email;
        if (!email)
          return res.status(400).send({ message: "email is required" });

        // users can only see their own reviews
        if (email !== req.tokenEmail)
          return res.status(403).send({ message: "Forbidden!" });

        const result = await reviewsCollection
          .find({ reviewerEmail: email })
          .sort({ date: -1 })
          .toArray();

        res.send(result);
      } catch (err) {
        console.error("/user-reviews GET error:", err);
        res.status(500).send({ message: "Failed to fetch user reviews" });
      }
    });

    // DELETE REVIEW (Protected)
    app.delete("/reviews/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid review id" });
        }

        const review = await reviewsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        // Only the owner can delete
        if (review.reviewerEmail !== req.tokenEmail) {
          return res.status(403).send({ message: "Forbidden!" });
        }

        await reviewsCollection.deleteOne({ _id: new ObjectId(id) });

        res.send({ success: true });
      } catch (err) {
        console.error("/reviews DELETE error:", err);
        res.status(500).send({ message: "Failed to delete review" });
      }
    });

    // UPDATE REVIEW (Protected)
    app.patch("/reviews/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const { rating, comment } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid review id" });
        }

        const review = await reviewsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        // Only owner can update
        if (review.reviewerEmail !== req.tokenEmail) {
          return res.status(403).send({ message: "Forbidden!" });
        }

        const updated = await reviewsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              rating,
              comment,
              date: new Date(),
            },
          }
        );

        res.send({ success: true, updated });
      } catch (err) {
        console.error("/reviews PATCH error:", err);
        res.status(500).send({ message: "Failed to update review" });
      }
    });

    // order request
    app.post("/order-requests", async (req, res) => {
      try {
        const orderData = req.body;

        const result = await orderRequestsCollection.insertOne(orderData);
        res.send(result);
      } catch (error) {
        console.error("/order-requests POST error:", error);
        res.status(500).send({ message: "Server Error" });
      }
    });

    // get all order request
    app.get("/order-requests", async (req, res) => {
      try {
        const result = await orderRequestsCollection.find().toArray();
        res.send(result);
      } catch (error) {
        console.error("/order-requests GET error:", error);
        res.status(500).send({ message: "Server Error" });
      }
    });

    // update payment status
    app.patch("/order-requests/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const { paymentStatus } = req.body;

        const result = await orderRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { paymentStatus } }
        );

        res.send(result);
      } catch (error) {
        console.error("/order-requests/:id PATCH error:", error);
        res.status(500).send({ message: "Server Error" });
      }
    });

    // GET ALL ORDERS FOR A CHEF BY EMAIL
    app.get("/orders/chef/:email", async (req, res) => {
      const email = req.params.email;

      const result = await ordersCollection
        .find({ chefEmail: email })
        .toArray();

      res.send(result);
    });

    // UPDATE ORDER STATUS (pending → accepted → delivered → cancelled)
    app.patch("/orders/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const { orderStatus } = req.body;

        const result = await ordersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { orderStatus } }
        );

        res.send(result);
      } catch (error) {
        console.error("/orders/:id PATCH error:", error);
        res.status(500).send({ message: "Server Error" });
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
