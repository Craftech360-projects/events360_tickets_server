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

// Add webhook handler for Razorpay events
app.post("/webhook/razorpay", async (req, res) => {
  try {
    const signature = req.headers["x-razorpay-signature"];
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

    // Verify webhook signature
    const crypto = require("crypto");
    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(JSON.stringify(req.body))
      .digest("hex");

    if (signature !== expectedSignature) {
      throw new Error("Invalid webhook signature");
    }

    const event = req.body;
    const orderId = event.payload.payment.entity.order_id;

    // Find the transaction
    const { data: transaction, error: txError } = await supabase
      .schema("public")
      .from("ticket_transactions")
      .select("*")
      .eq("razorpay_order_id", orderId)
      .single();

    if (txError) throw txError;

    // Log the webhook event
    await supabase
      .schema("public")
      .from("payment_logs")
      .update({
        webhook_events: supabase.raw("array_append(webhook_events, ?)", [
          event,
        ]),
        updated_at: new Date(),
      })
      .eq("transaction_id", transaction.id);

    // Handle different event types
    switch (event.event) {
      case "payment.captured":
        await handlePaymentSuccess(transaction.id, event);
        break;
      case "payment.failed":
        await handlePaymentFailure(transaction.id, event);
        break;
      case "refund.processed":
        await handleRefundSuccess(transaction.id, event);
        break;
    }

    res.json({ received: true });
  } catch (error) {
    console.error("Webhook error:", error);
    res.status(500).json({ error: error.message });
  }
});

async function handlePaymentSuccess(transactionId, event) {
  const payment = event.payload.payment.entity;

  // Check if payment was already processed
  const { data: existingBooking } = await supabase
    .schema("public")
    .from("bookings")
    .select()
    .eq("payment_reference", payment.id)
    .single();

  if (existingBooking) {
    console.log("Payment already processed:", payment.id);
    return;
  }

  // Process the payment
  const { error } = await supabase.rpc("process_ticket_purchase", {
    p_transaction_id: transactionId,
    p_payment_id: payment.id,
    p_signature: payment.signature,
  });

  if (error) {
    // Log failure for manual investigation
    await supabase
      .schema("public")
      .from("payment_logs")
      .insert({
        transaction_id: transactionId,
        razorpay_order_id: payment.order_id,
        razorpay_payment_id: payment.id,
        amount: payment.amount / 100,
        status: "failed",
        last_error: error.message,
      });
  }
}

async function handlePaymentFailure(transactionId, event) {
  const payment = event.payload.payment.entity;

  await supabase
    .schema("public")
    .from("payment_logs")
    .insert({
      transaction_id: transactionId,
      razorpay_order_id: payment.order_id,
      razorpay_payment_id: payment.id,
      amount: payment.amount / 100,
      status: "failed",
      last_error: payment.error_description,
    });

  // Update transaction status
  await supabase
    .schema("public")
    .from("ticket_transactions")
    .update({ status: "failed" })
    .eq("id", transactionId);
}

async function handleRefundSuccess(transactionId, event) {
  const refund = event.payload.refund.entity;

  await supabase
    .schema("public")
    .from("payment_logs")
    .insert({
      transaction_id: transactionId,
      razorpay_order_id: refund.order_id,
      razorpay_payment_id: refund.payment_id,
      amount: refund.amount / 100,
      status: "refunded",
    });

  // Update transaction status
  await supabase
    .schema("public")
    .from("ticket_transactions")
    .update({ status: "refunded" })
    .eq("id", transactionId);
}

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
    const { ticketId, quantity, organizationId, userDetails } = req.body;

    // Validate required fields
    const requiredFields = {
      ticketId: "Ticket ID",
      quantity: "Quantity",
      organizationId: "Organization ID",
      "userDetails.name": "Customer Name",
      "userDetails.email": "Email",
      "userDetails.phone": "Phone Number",
    };

    const missingFields = Object.entries(requiredFields)
      .filter(([key]) => !key.split(".").reduce((obj, k) => obj?.[k], req.body))
      .map(([, label]) => label);

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Missing required fields: ${missingFields.join(", ")}`,
      });
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

    // Create transaction record with user details
    const { data: transaction, error: txError } = await supabase
      .from("ticket_transactions")
      .insert({
        ticket_id: ticketId,
        quantity: quantity,
        unit_price: ticketData.price,
        total_amount: price * quantity,
        status: "pending",
        customer_name: userDetails.name,
        customer_email: userDetails.email,
        customer_phone: userDetails.phone,
        ticket_type: ticketData.ticket_type,
        event_name: ticketData.events.name,
        purchase_date: new Date().toISOString(),
        organization_id: organizationId,
      })
      .select()
      .single();

    if (txError) throw txError;

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

    res.json({
      paymentIntent: {
        key_id: process.env.RAZORPAY_KEY_ID,
        order_id: orderData.id,
        amount,
        currency: "INR",
        name: ticketData.name,
        description: `${quantity}x ${ticketData.name}`,
        prefill: {
          name: userDetails.name,
          email: userDetails.email,
          contact: userDetails.phone,
        },
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
