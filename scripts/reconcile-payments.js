const { createClient } = require("@supabase/supabase-js");
const Razorpay = require("razorpay");
require("dotenv").config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    db: { schema: "public" },
  }
);

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

async function reconcilePayments() {
  // Get pending transactions older than 5 minutes
  const { data: pendingTxns, error } = await supabase
    .from("ticket_transactions")
    .select("*")
    .eq("status", "pending")
    .lt("created_at", new Date(Date.now() - 5 * 60 * 1000).toISOString());

  if (error) throw error;

  for (const txn of pendingTxns) {
    try {
      // Check payment status in Razorpay
      const payment = await razorpay.orders.fetch(txn.razorpay_order_id);

      if (payment.status === "paid") {
        // Payment successful but not processed
        await handlePaymentSuccess(txn.id, {
          payload: { payment: { entity: payment } },
        });
      } else if (payment.status === "failed") {
        // Payment failed
        await handlePaymentFailure(txn.id, {
          payload: { payment: { entity: payment } },
        });
      }
    } catch (error) {
      console.error(`Reconciliation failed for transaction ${txn.id}:`, error);
    }
  }
}

// Run reconciliation
reconcilePayments().catch(console.error);
