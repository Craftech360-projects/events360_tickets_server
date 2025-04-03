const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3003;

// Initialize Supabase client

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    db: { schema: "admin" },
  }
);

// Use admin schema for widget_keys and tickets
const adminDb = getSupabaseClient("admin");
// Use public schema for transactions and users
const publicDb = getSupabaseClient("public");

app.use(
  cors({
    origin: ["http://localhost:8000", "http://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-API-Key", "X-Organization-ID"],
  })
);

app.use(express.json());

// Validate API key
app.get("/validate-key", async (req, res) => {
  try {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey) {
      console.log("No API key provided");
      return res.status(401).json({ error: "API key is required" });
    }

    const { data, error } = await supabase
      .from("widget_keys")
      .select("organization_id, event_id, expires_at")
      .eq("api_key", apiKey)
      .single();

    if (error) {
      console.log("Supabase error:", error);
      throw error;
    }

    const expiresAt = new Date(data.expires_at);
    if (expiresAt < new Date()) {
      console.log("API key expired at:", expiresAt);
      return res.status(401).json({ error: "API key has expired" });
    }

    const response = {
      organizationId: data.organization_id,
      eventId: data.event_id,
    };

    res.json(response);
  } catch (error) {
    console.log("Validation error:", error);
    res.status(401).json({ error: "Invalid API key" });
  }
});

// Get tickets
app.get("/tickets/:eventId", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("tickets")
      .select()
      .eq("event_id", req.params.eventId)
      .eq("is_active", true);

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch tickets" });
  }
});

app.post("/verify-payment", async (req, res) => {
  try {
    const {
      razorpay_payment_id,
      razorpay_order_id,
      razorpay_signature,
      transaction_id,
    } = req.body;

    // 1. Get transaction details
    const { data: transaction, error: txError } = await supabase
      .from("ticket_transactions")
      .select("*, tickets(*)")
      .eq("id", transaction_id)
      .single();

    if (txError) throw txError;

    // 2. Verify payment signature
    const text = `${razorpay_order_id}|${razorpay_payment_id}`;
    const crypto = require("crypto");
    const generated_signature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(text)
      .digest("hex");

    if (generated_signature !== razorpay_signature) {
      throw new Error("Invalid payment signature");
    }

    // 3. Begin transaction
    const { error: dbError } = await supabase.rpc("process_ticket_purchase", {
      p_transaction_id: transaction_id,
      p_payment_id: razorpay_payment_id,
      p_signature: razorpay_signature,
    });

    if (dbError) throw dbError;

    res.json({ success: true });
  } catch (error) {
    console.error("Payment verification error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Purchase ticket
app.post("/purchase", async (req, res) => {
  try {
    const { ticketId, quantity, organizationId, userId } = req.body;

    if (!ticketId || !quantity || !organizationId || !userId) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const { data: ticketData, error: ticketError } = await supabase
      .from("tickets")
      .select()
      .eq("id", ticketId)
      .eq("organization_id", organizationId)
      .single();

    if (ticketError) throw ticketError;

    if (ticketData.available_quantity < quantity) {
      return res.status(400).json({ error: "Insufficient tickets available" });
    }

    if (quantity > ticketData.max_tickets_per_user) {
      return res.status(400).json({
        error: `Maximum ${ticketData.max_tickets_per_user} tickets allowed per user`,
      });
    }

    const price = parseFloat(ticketData.price) || 0.0;
    const amount = Math.floor(price * quantity * 100);

    // Create Razorpay order
    const authString = `${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`;
    const basicAuth = Buffer.from(authString).toString("base64");

    const orderResponse = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${basicAuth}`,
      },
      body: JSON.stringify({
        amount,
        currency: "INR",
        receipt: `order_${Date.now()}`,
        partial_payment: false,
        notes: {
          ticketId,
          quantity,
          organizationId,
        },
      }),
    });

    if (!orderResponse.ok) {
      const error = await orderResponse.json();
      throw new Error(`Razorpay error: ${error.error.description}`);
    }

    const orderData = await orderResponse.json();

    // Create transaction record
    const { data: transaction, error: txError } = await supabase
      .from("ticket_transactions")
      .insert({
        ticket_id: ticketId,
        user_id: userId, // This variable is undefined - needs to be passed from client
        quantity: quantity,
        unit_price: ticketData.price,
        total_amount: price * quantity,
        razorpay_order_id: orderData.id,
        status: "pending",
      })
      .select()
      .single();

    if (txError) throw txError;

    res.json({
      paymentIntent: {
        key_id: process.env.RAZORPAY_KEY_ID,
        order_id: orderData.id,
        amount,
        currency: "INR",
        name: ticketData.name,
        description: `${quantity}x ${ticketData.name}`,
        prefill: { contact: "", email: "" },
      },
      transaction_id: transaction.id,
    });
  } catch (error) {
    console.error("Payment error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`API server running on port ${port}`);
});
