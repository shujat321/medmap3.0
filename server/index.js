import dotenv from "dotenv";
dotenv.config({ override: true });
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createServer as createViteServer } from "vite";
import { User, Pharmacy, Medicine, Stock, Order } from "./models.js";
import { protect, allow } from "./auth.js";
import { seedDefaults } from "./seed.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

const app = express();
const allowedOrigin = process.env.CORS_ORIGIN || process.env.FRONTEND_URL;
app.use(cors({
  origin: allowedOrigin ? allowedOrigin.split(",").map(o => o.trim()) : true,
  credentials: true
}));
app.use(express.json({ limit: "1mb" }));
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const safeUser = u => ({ id: u._id, userId: u.userId, name: u.name, email: u.email, role: u.role, pharmacyId: u.pharmacyId });
const tokenFor = u => jwt.sign({ id: u._id }, process.env.JWT_SECRET || "development-only-secret", { expiresIn: "12h" });

app.get("/api/health", (req, res) => {
  const isConnected = mongoose.connection.readyState === 1;
  res.json({
    ok: true,
    app: "MedMap API",
    database: {
      connected: isConnected,
      readyState: mongoose.connection.readyState,
      mode: isConnected ? "MongoDB Atlas" : "In-Memory",
      host: isConnected ? mongoose.connection.host : null,
      name: isConnected ? mongoose.connection.name : null
    }
  });
});

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const { loginId, password } = req.body;
  if (!loginId || !password) return res.status(400).json({ message: "Enter your ID/email and password." });
  const user = await User.findOne({ $or: [{ userId: String(loginId) }, { email: String(loginId).toLowerCase() }] });
  if (!user || !(await bcrypt.compare(String(password), user.passwordHash))) return res.status(401).json({ message: "Invalid ID/email or password." });
  res.json({ token: tokenFor(user), user: safeUser(user) });
}));
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name?.trim() || !email?.trim() || !password || String(password).length < 6) return res.status(400).json({ message: "Name, valid email and a password of at least 6 characters are required." });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ message: "An account with this email already exists." });
  const user = await User.create({ name: name.trim(), email: email.toLowerCase().trim(), role: "patient", passwordHash: await bcrypt.hash(String(password), 10) });
  res.status(201).json({ token: tokenFor(user), user: safeUser(user) });
}));
app.get("/api/auth/me", protect, (req, res) => res.json({ user: safeUser(req.user) }));

app.get("/api/pharmacies", asyncRoute(async (req, res) => {
  const query = { active: true };
  if (req.query.city) query.city = new RegExp(String(req.query.city), "i");
  const pharmacies = await Pharmacy.find(query).populate("pharmacistId", "name userId").sort({ name: 1 });
  res.json(pharmacies);
}));
app.post("/api/pharmacies", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const { name, address, city, phone } = req.body;
  if (!name?.trim() || !address?.trim() || !city?.trim()) return res.status(400).json({ message: "Pharmacy name, address and city are required." });
  const owner = req.user.role === "pharmacist" ? req.user._id : null;
  const pharmacy = await Pharmacy.create({ name: name.trim(), address: address.trim(), city: city.trim(), phone: phone || "", pharmacistId: owner });
  if (owner && !req.user.pharmacyId) { req.user.pharmacyId = pharmacy._id; await req.user.save(); }
  res.status(201).json(pharmacy);
}));
app.patch("/api/pharmacies/:id", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const pharmacy = await Pharmacy.findById(req.params.id);
  if (!pharmacy) return res.status(404).json({ message: "Pharmacy not found." });
  if (req.user.role === "pharmacist" && String(pharmacy.pharmacistId) !== String(req.user._id)) return res.status(403).json({ message: "You can edit only pharmacies assigned to you." });
  const allowed = ["name", "address", "city", "phone", "active"];
  for (const key of allowed) if (req.body[key] !== undefined) pharmacy[key] = req.body[key];
  await pharmacy.save(); res.json(pharmacy);
}));
app.delete("/api/pharmacies/:id", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const pharmacy = await Pharmacy.findById(req.params.id);
  if (!pharmacy) return res.status(404).json({ message: "Pharmacy not found." });
  if (req.user.role === "pharmacist" && String(pharmacy.pharmacistId) !== String(req.user._id)) return res.status(403).json({ message: "You can remove only pharmacies assigned to you." });
  // Preserve past orders; deactivate instead of destroying their history.
  pharmacy.active = false; await pharmacy.save();
  res.json({ message: "Pharmacy removed from public listings." });
}));

app.get("/api/medicines", asyncRoute(async (req, res) => {
  const q = String(req.query.q || "").trim();
  const meds = await Medicine.find(q ? { $or: [{ name: new RegExp(q, "i") }, { brand: new RegExp(q, "i") }, { category: new RegExp(q, "i") }] } : {}).sort({ name: 1 });
  res.json(meds);
}));
app.post("/api/medicines", protect, allow("admin"), asyncRoute(async (req, res) => {
  const { name, brand, category, description, prescriptionRequired } = req.body;
  if (!name?.trim()) return res.status(400).json({ message: "Medicine name is required." });
  const med = await Medicine.create({ name: name.trim(), brand: brand || "", category: category || "General", description: description || "", prescriptionRequired: Boolean(prescriptionRequired) });
  res.status(201).json(med);
}));
app.patch("/api/medicines/:id", protect, allow("admin"), asyncRoute(async (req, res) => {
  const med = await Medicine.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true, runValidators: true });
  if (!med) return res.status(404).json({ message: "Medicine not found." }); res.json(med);
}));
app.delete("/api/medicines/:id", protect, allow("admin"), asyncRoute(async (req, res) => {
  const med = await Medicine.findByIdAndDelete(req.params.id);
  if (!med) return res.status(404).json({ message: "Medicine not found." });
  await Stock.deleteMany({ medicineId: med._id });
  res.json({ message: "Medicine and related stock records deleted." });
}));

app.get("/api/stock", asyncRoute(async (req, res) => {
  const filter = {};
  if (req.query.pharmacyId) filter.pharmacyId = req.query.pharmacyId;
  const stock = await Stock.find(filter).populate("medicineId").populate("pharmacyId", "name address city active").sort({ updatedAt: -1 });
  res.json(stock.filter(s => s.pharmacyId?.active));
}));
app.post("/api/stock", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const { pharmacyId, medicineId, quantity, price } = req.body;
  if (!pharmacyId || !medicineId || !Number.isInteger(Number(quantity)) || Number(quantity) < 0 || !Number.isFinite(Number(price)) || Number(price) < 0) return res.status(400).json({ message: "Choose a pharmacy and medicine; quantity and price must be valid non-negative numbers." });
  const pharmacy = await Pharmacy.findById(pharmacyId);
  if (!pharmacy || !pharmacy.active) return res.status(404).json({ message: "Active pharmacy not found." });
  if (req.user.role === "pharmacist" && String(pharmacy.pharmacistId) !== String(req.user._id)) return res.status(403).json({ message: "You can update stock only for pharmacies assigned to you." });
  const med = await Medicine.findById(medicineId);
  if (!med) return res.status(404).json({ message: "Medicine not found." });
  const stock = await Stock.findOneAndUpdate({ pharmacyId, medicineId }, { $set: { quantity: Number(quantity), price: Number(price), updatedBy: req.user._id } }, { upsert: true, new: true, runValidators: true });
  res.json(await stock.populate(["medicineId", "pharmacyId"]));
}));
app.delete("/api/stock/:id", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const stock = await Stock.findById(req.params.id).populate("pharmacyId");
  if (!stock) return res.status(404).json({ message: "Stock record not found." });
  if (req.user.role === "pharmacist" && String(stock.pharmacyId.pharmacistId) !== String(req.user._id)) return res.status(403).json({ message: "You can remove stock only for your pharmacy." });
  await stock.deleteOne(); res.json({ message: "Stock entry removed." });
}));

app.post("/api/orders", protect, allow("patient", "admin"), asyncRoute(async (req, res) => {
  const { pharmacyId, items, patientName, patientPhone, deliveryAddress, paymentMethod, hasPrescription } = req.body;
  if (!pharmacyId || !Array.isArray(items) || !items.length) return res.status(400).json({ message: "Select a pharmacy and at least one medicine." });
  const cleanName = String(patientName || req.user?.name || "").trim();
  const cleanPhone = String(patientPhone || "").trim();
  const cleanAddress = String(deliveryAddress || "").trim();
  if (!cleanName || !cleanPhone || !cleanAddress) return res.status(400).json({ message: "Full name, phone number and delivery address are required." });
  if (!/^[0-9+()\- ]{10,16}$/.test(cleanPhone)) return res.status(400).json({ message: "Enter a valid contact phone number." });
  const validMethods = ["Cash on delivery", "UPI at pharmacy", "Card at pharmacy"];
  const finalPayment = validMethods.includes(paymentMethod) ? paymentMethod : "Cash on delivery";
  const pharmacy = await Pharmacy.findOne({ _id: pharmacyId, active: true });
  if (!pharmacy) return res.status(404).json({ message: "Selected pharmacy is not available." });
  const finalItems = []; let total = 0;
  for (const item of items) {
    const qty = Number(item.quantity);
    if (!Number.isInteger(qty) || qty < 1) return res.status(400).json({ message: "Order quantities must be whole numbers greater than zero." });
    const stock = await Stock.findOne({ pharmacyId, medicineId: item.medicineId }).populate("medicineId");
    if (!stock || stock.quantity < qty) return res.status(400).json({ message: `${stock?.medicineId?.name || "A selected medicine"} does not have enough stock.` });
    if (stock.medicineId.prescriptionRequired && !hasPrescription) return res.status(400).json({ message: `${stock.medicineId.name} requires a doctor prescription.` });
    finalItems.push({ medicineId: stock.medicineId._id, name: stock.medicineId.name, quantity: qty, price: stock.price });
    total += qty * stock.price;
  }
  // Reduce inventory before creating the order
  for (const item of finalItems) {
    const result = await Stock.updateOne({ pharmacyId, medicineId: item.medicineId, quantity: { $gte: item.quantity } }, { $inc: { quantity: -item.quantity } });
    if (!result.modifiedCount) return res.status(409).json({ message: "Stock changed while placing your order. Refresh and try again." });
  }
  const order = await Order.create({ patientId: req.user._id, pharmacyId, pharmacistId: pharmacy.pharmacistId, items: finalItems, total, patientName: cleanName, patientPhone: cleanPhone, deliveryAddress: cleanAddress, paymentMethod: finalPayment });
  res.status(201).json(await order.populate(["pharmacyId", "pharmacistId"]));
}));
app.get("/api/orders/mine", protect, asyncRoute(async (req, res) => {
  res.json(await Order.find({ patientId: req.user._id }).populate("pharmacyId", "name city address").sort({ createdAt: -1 }));
}));
app.get("/api/orders", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const filter = {};
  if (req.user.role === "pharmacist") filter.pharmacistId = req.user._id;
  res.json(await Order.find(filter).populate("pharmacyId", "name city address").populate("patientId", "name email").sort({ createdAt: -1 }));
}));
app.patch("/api/orders/:id/status", protect, allow("admin", "pharmacist"), asyncRoute(async (req, res) => {
  const allowedStatuses = ["Accepted", "Ready", "Completed", "Cancelled"];
  if (!allowedStatuses.includes(req.body.status)) return res.status(400).json({ message: "Invalid order status." });
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ message: "Order not found." });
  if (req.user.role === "pharmacist" && String(order.pharmacistId) !== String(req.user._id)) return res.status(403).json({ message: "This order belongs to another pharmacist." });
  if (order.status === "Completed" || order.status === "Cancelled") return res.status(400).json({ message: "This order is already closed." });
  order.status = req.body.status; await order.save(); res.json(order);
}));

app.use((err, req, res, next) => {
  console.error("[MedMap Server Error]:", err.message || err);
  if (err?.name === "MongooseError" || err?.name === "MongoNetworkError" || err?.message?.includes("buffering timed out")) {
    return res.status(503).json({
      message: "Database connection unavailable. Please verify MONGODB_URI and MongoDB Atlas network access."
    });
  }
  if (err?.code === 11000) return res.status(409).json({ message: "This record already exists." });
  if (err?.name === "CastError") return res.status(400).json({ message: "Invalid record ID." });
  res.status(500).json({ message: err.message || "Internal server error." });
});

let databaseReady = null;
export async function ensureDatabase() {
  if (mongoose.connection.readyState === 1) return mongoose.connection;
  if (databaseReady) return databaseReady;

  databaseReady = (async () => {
    const uri = process.env.MONGODB_URI;
    if (!uri) {
      console.warn("[MedMap] Warning: MONGODB_URI is not set in environment variables.");
      return;
    }
    const sanitized = uri.replace(/:([^:@]+)@/, ":****@");
    console.log(`[MedMap] Connecting to MongoDB Atlas: ${sanitized.split("@")[1] || "cluster"}...`);
    mongoose.set("bufferCommands", false);
    const connectOpts = { serverSelectionTimeoutMS: 10000 };
    const pathPart = uri.split("?")[0].replace(/^mongodb(\+srv)?:\/\/[^/]+\/?/, "").trim();
    if (!pathPart) connectOpts.dbName = "medmap";

    try {
      await mongoose.connect(uri, connectOpts);
      console.log(`[MedMap] MongoDB connected successfully to database: ${mongoose.connection.name}`);
      await seedDefaults();
      console.log("[MedMap] Database seed check completed.");
    } catch (err) {
      console.error("[MedMap] MongoDB Atlas connection error:", err.message);
      databaseReady = null;
      throw err;
    }
  })();

  return databaseReady;
}

export async function createFullApp() {
  try {
    await ensureDatabase();
  } catch (err) {
    console.warn("[MedMap] Initial database connection attempt failed; will retry on incoming API requests:", err.message);
  }

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      root: rootDir,
      server: { middlewareMode: true, host: "0.0.0.0" },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(rootDir, "dist");
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get("*", (req, res) => {
        res.sendFile(path.resolve(distPath, "index.html"));
      });
    }
  }

  return app;
}

export default app;

if (process.env.VERCEL !== "1") {
  let port = Number(process.env.PORT);
  if (!port || Number.isNaN(port)) {
    const portArgIndex = process.argv.indexOf("--port");
    if (portArgIndex !== -1 && process.argv[portArgIndex + 1]) {
      port = Number(process.argv[portArgIndex + 1]);
    }
  }
  if (!port || Number.isNaN(port)) port = 3000;

  createFullApp()
    .then(serverApp => {
      serverApp.listen(port, "0.0.0.0", () => {
        console.log(`MedMap running on http://0.0.0.0:${port}`);
      });
    })
    .catch(err => {
      console.error("Fatal startup error:", err);
      process.exit(1);
    });
}
