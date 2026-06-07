import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bodyParser from "body-parser";
import crypto from "node:crypto";
import dns from "node:dns";
import mongoose from "mongoose";
import OpenAI from "openai";

dns.setDefaultResultOrder("ipv4first");
dns.setServers(["8.8.8.8", "1.1.1.1"]);

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.redirect("/admin");
});

app.get("/admin", (req, res) => {
  res.redirect("/admin.html");
});

app.get("/b/:businessId", (req, res) => {
  res.sendFile("chat.html", { root: "public" });
});

// 🔑 OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// 🧠 MULTI-USER MEMORY
const AUTH_SECRET = process.env.AUTH_SECRET || process.env.JWT_SECRET || "dev-secret-change-me";
const userMemory = {};

const businessSchema = new mongoose.Schema(
  {
    businessId: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password_hash: { type: String, required: true, select: false },
    name: { type: String, required: true, trim: true },
    currency: { type: String, default: "$", trim: true },
    tone: { type: String, default: "friendly", trim: true },
    description: { type: String, default: "", trim: true },
    contact_info: { type: String, default: "", trim: true },
    notification_email: { type: String, default: "", lowercase: true, trim: true },
    ai_personality: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

const Business = mongoose.model("Business", businessSchema);

function base64Url(input) {
  return Buffer.from(input).toString("base64url");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(":");
  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, "hex");

  return expected.length === candidate.length && crypto.timingSafeEqual(expected, candidate);
}

function signToken(payload) {
  const encodedPayload = base64Url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encodedPayload)
    .digest("base64url");

  return `${encodedPayload}.${signature}`;
}

function verifyToken(token) {
  const [encodedPayload, signature] = token.split(".");

  if (!encodedPayload || !signature) {
    return null;
  }

  const expectedSignature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encodedPayload)
    .digest("base64url");

  const providedSignature = Buffer.from(signature);
  const validSignature = Buffer.from(expectedSignature);

  if (
    providedSignature.length !== validSignature.length ||
    !crypto.timingSafeEqual(providedSignature, validSignature)
  ) {
    return null;
  }

  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));

  if (payload.exp && Date.now() > payload.exp) {
    return null;
  }

  return payload;
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  return scheme === "Bearer" && token ? token : null;
}

function publicBusinessProfile(business) {
  const data = business.toObject ? business.toObject() : { ...business };
  delete data.password_hash;
  return data;
}

async function requireAuth(req, res, next) {
  try {
    const token = getBearerToken(req);
    const payload = token ? verifyToken(token) : null;

    if (!payload?.businessId) {
      return res.status(401).json({ error: "Authentication required." });
    }

    const business = await Business.findOne({ businessId: payload.businessId }).lean();

    if (!business) {
      return res.status(401).json({ error: "Invalid authentication token." });
    }

    req.business = business;
    req.businessId = business.businessId;
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid authentication token." });
  }
}

function requireMatchingBusiness(req, res, businessId) {
  if (businessId && businessId !== req.businessId) {
    res.status(403).json({ error: "You can only access your own business data." });
    return false;
  }

  return true;
}

const productSchema = new mongoose.Schema(
  {
    businessId: { type: String, required: true, index: true },
    type: { type: String, enum: ["product", "service"], default: "product", index: true },
    name: { type: String, required: true, trim: true },
    option: { type: String, default: "", trim: true },
    aliases: { type: [String], default: [] },
    price: { type: Number, required: true, min: 0 },
    stock_quantity: { type: Number, default: 0, min: 0 },
    duration: { type: String, default: "", trim: true },
    requires_booking_time: { type: Boolean, default: false },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

productSchema.index({ businessId: 1, name: 1, option: 1 }, { unique: true });

const Product = mongoose.model("Product", productSchema);

const orderItemSchema = new mongoose.Schema(
  {
    product_id: { type: mongoose.Schema.Types.ObjectId, required: true, ref: "Product" },
    type: { type: String, enum: ["product", "service"], default: "product" },
    product: { type: String, required: true },
    quantity: { type: Number, required: true },
    unit_price: { type: Number, required: true },
    total_price: { type: Number, required: true },
    duration: { type: String, default: "" },
  },
  { _id: false }
);

const customerSchema = new mongoose.Schema(
  {
    name: { type: String, default: "", trim: true },
    phone: { type: String, default: "", trim: true },
    address: { type: String, default: "", trim: true },
    preferred_date: { type: String, default: "", trim: true },
    preferred_time: { type: String, default: "", trim: true },
    note: { type: String, default: "", trim: true },
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    order_id: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true },
    businessId: { type: String, required: true, index: true },
    customer: { type: customerSchema, default: () => ({}) },
    items: { type: [orderItemSchema], required: true },
    total_price: { type: Number, required: true },
    status: { type: String, default: "placed" },
  },
  { timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

orderSchema.index({ businessId: 1, order_id: 1 }, { unique: true });

const Order = mongoose.model("Order", orderSchema);

const orderCounterSchema = new mongoose.Schema(
  {
    businessId: { type: String, required: true },
    date: { type: String, required: true },
    sequence: { type: Number, default: 0 },
  },
  { timestamps: true }
);

orderCounterSchema.index({ businessId: 1, date: 1 }, { unique: true });

const OrderCounter = mongoose.model("OrderCounter", orderCounterSchema);

async function ensureOfferingIndexes() {
  try {
    const indexes = await Product.collection.indexes();
    const oldNameIndex = indexes.find(index =>
      index.name === "businessId_1_name_1" &&
      index.unique &&
      index.key?.businessId === 1 &&
      index.key?.name === 1 &&
      index.key?.option === undefined
    );

    if (oldNameIndex) {
      await Product.collection.dropIndex(oldNameIndex.name);
      console.log("Dropped old unique offering name index");
    }

    await Product.collection.createIndex(
      { businessId: 1, name: 1, option: 1 },
      { unique: true, name: "businessId_1_name_1_option_1" }
    );
  } catch (error) {
    console.warn("Offering index check warning:", error.message);
  }
}

// ✅ BETTER YES / NO DETECTION
function isYes(message) {
  return /(yes|yeah|yep|sure|ok|okay|confirm|go ahead|do it|proceed|sounds good|do that)/i.test(message);
}

function isNo(message) {
  return /(no|nah|cancel|stop|don’t|dont|never mind)/i.test(message);
}

function isOrderRequest(message) {
  return /\b(i want|i need|i would like|i will like|i'll like|buy|order|get|take|purchase|go for|choose|pick)\b/.test(message);
}

// ✅ EXTRACT QUANTITY
function isPriceRequest(message) {
  return /\b(how much|price|cost|amount|rate)\b/.test(message);
}

function isBrowseRequest(message) {
  return /\b(what|show|list|see)\b.*\b(have|sell|available|offer|products|items|menu|catalog)\b/.test(message) ||
    /\b(menu|catalog|products|items)\b/.test(message);
}

function isBroadCatalogRequest(message) {
  return isBrowseRequest(message) && !/\b(specific|particular|only)\b/i.test(message);
}

function isCatalogConfirmationFollowup(message) {
  return /\b(are you sure|is that all|only that|that's all|that is all|is this all)\b/i.test(message);
}

function buildBusinessChatFollowup(reply, products) {
  const normalizedReply = (reply || "").toLowerCase();
  const mentionedProducts = products.filter(product =>
    normalizedReply.includes(product.name.toLowerCase())
  );
  const offersMoreInfo = /\b(want|would you like|like to|interested|know more|tell me more|more about)\b/i.test(reply || "");

  if (mentionedProducts.length > 0 && offersMoreInfo) {
    return {
      action: "show_catalog",
    };
  }

  return null;
}

function isGreetingOnly(message) {
  return /^(hi|hello|hey|sup|yo|good morning|good afternoon|good evening)\b[!.?\s]*$/i.test(message.trim());
}

function extractQuantity(message) {
  const match = message.match(/\d+/);
  if (match) {
    return parseInt(match[0]);
  }

  return parseNumberWords(message);
}

function parseNumberWords(message) {
  const smallNumbers = {
    a: 1,
    an: 1,
    one: 1,
    two: 2,
    three: 3,
    four: 4,
    five: 5,
    six: 6,
    seven: 7,
    eight: 8,
    nine: 9,
    ten: 10,
    eleven: 11,
    twelve: 12,
    thirteen: 13,
    fourteen: 14,
    fifteen: 15,
    sixteen: 16,
    seventeen: 17,
    eighteen: 18,
    nineteen: 19,
  };

  const tens = {
    twenty: 20,
    thirty: 30,
    forty: 40,
    fifty: 50,
    sixty: 60,
    seventy: 70,
    eighty: 80,
    ninety: 90,
  };

  const scales = {
    hundred: 100,
    thousand: 1000,
    million: 1000000,
    billion: 1000000000,
  };

  const tokens = message
    .toLowerCase()
    .replace(/-/g, " ")
    .replace(/[^\w\s]/g, " ")
    .split(/\s+/)
    .filter(Boolean);

  let total = 0;
  let current = 0;
  let foundNumber = false;

  for (const token of tokens) {
    if (token === "and") {
      continue;
    }

    if (smallNumbers[token]) {
      current += smallNumbers[token];
      foundNumber = true;
      continue;
    }

    if (tens[token]) {
      current += tens[token];
      foundNumber = true;
      continue;
    }

    if (token === "hundred") {
      current = (current || 1) * scales.hundred;
      foundNumber = true;
      continue;
    }

    if (token === "thousand" || token === "million" || token === "billion") {
      total += (current || 1) * scales[token];
      current = 0;
      foundNumber = true;
      continue;
    }
  }

  const quantity = total + current;
  return foundNumber && quantity > 0 ? quantity : null;
}

// ✅ EXTRACT PRODUCT (NEW)
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getProductNameVariants(name) {
  const normalizedName = name.toLowerCase().trim();
  const variants = new Set([normalizedName]);

  if (normalizedName.endsWith("s")) {
    variants.add(normalizedName.slice(0, -1));
  } else {
    variants.add(`${normalizedName}s`);
  }

  return [...variants].sort((a, b) => b.length - a.length);
}

function normalizeAliases(aliases) {
  if (Array.isArray(aliases)) {
    return [...new Set(
      aliases
        .map(alias => String(alias).toLowerCase().trim())
        .filter(Boolean)
    )];
  }

  if (typeof aliases === "string") {
    return normalizeAliases(aliases.split(","));
  }

  return [];
}

function getProductSearchTerms(product) {
  return [product.name, product.option, offeringDisplayName(product), ...(product.aliases || [])]
    .filter(Boolean)
    .flatMap(term => getProductNameVariants(term))
    .filter(Boolean);
}

function productSearchRegex(product) {
  const variants = getProductSearchTerms(product).map(escapeRegExp);
  return new RegExp(`\\b(?:${variants.join("|")})\\b`, "i");
}

function productNameRegex(name) {
  const variants = getProductNameVariants(name).map(escapeRegExp);
  return new RegExp(`\\b(?:${variants.join("|")})\\b`, "i");
}

function findProductByName(name, products) {
  const normalizedName = name.toLowerCase().trim();
  const matches = products.filter(product =>
    getProductSearchTerms(product).includes(normalizedName)
  );

  return matches.length === 1 ? matches[0] : null;
}

function getProductKeywords(product) {
  return [...new Set(
    [product.name, product.option, ...(product.aliases || [])]
      .join(" ")
      .toLowerCase()
      .split(/\s+/)
      .flatMap(word => getProductNameVariants(word))
      .filter(word => word.length > 1)
  )];
}

function hasWord(message, word) {
  return new RegExp(`\\b${escapeRegExp(word)}\\b`, "i").test(message);
}

function getOptionKeywords(product) {
  return normalizeOfferingOption(product?.option)
    .split(/\s+/)
    .filter(word => word.length > 2 && !["with", "and", "the", "for"].includes(word));
}

function resolveUniqueOptionProduct(message, products) {
  const matches = products.filter(product =>
    getOptionKeywords(product).some(keyword => hasWord(message, keyword))
  );

  return matches.length === 1 ? matches[0] : null;
}

function formatProductChoices(products, currency = "$") {
  const displayNames = products.map(product => offeringDisplayName(product));
  const duplicateNames = new Set(
    displayNames.filter((name, index) => displayNames.indexOf(name) !== index)
  );
  const names = products.map(product => {
    const displayName = offeringDisplayName(product);

    if (!duplicateNames.has(displayName)) {
      return displayName;
    }

    const duration = product.duration ? `, ${product.duration}` : "";
    return `${displayName} (${formatMoney(product.price, currency)}${duration})`;
  });

  if (names.length <= 2) {
    return names.join(" or ");
  }

  return `${names.slice(0, -1).join(", ")}, or ${names[names.length - 1]}`;
}

function formatMoney(amount, currency = "$") {
  const numericAmount = Number(amount) || 0;
  const fractionDigits = Number.isInteger(numericAmount) ? 0 : 2;

  return `${currency}${numericAmount.toLocaleString("en-US", {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  })}`;
}

function isServiceOffering(product) {
  return product?.type === "service";
}

function normalizedOfferingType(type) {
  return type === "service" ? "service" : "product";
}

function normalizeOfferingOption(option) {
  return String(option || "").toLowerCase().trim();
}

function offeringDisplayName(product) {
  const option = normalizeOfferingOption(product?.option);
  return option ? `${product.name} - ${option}` : product.name;
}

function orderQuantityForOffering(product, quantity) {
  const numericQuantity = Number(quantity);

  if (Number.isInteger(numericQuantity) && numericQuantity > 0) {
    return numericQuantity;
  }

  return isServiceOffering(product) ? 1 : null;
}

function formatProductCatalog(products, currency = "$") {
  return products
    .map(product => {
      const displayName = offeringDisplayName(product);

      if (isServiceOffering(product)) {
        const duration = product.duration ? `, ${product.duration}` : "";
        const booking = product.requires_booking_time ? ", booking time needed" : "";
        return `- ${displayName}: ${formatMoney(product.price, currency)}${duration}${booking}`;
      }

      return `- ${displayName}: ${formatMoney(product.price, currency)} (${product.stock_quantity} in stock)`;
    })
    .join("\n");
}

function sanitizeCustomerInfo(customer = {}) {
  return {
    name: String(customer.name || "").trim().slice(0, 120),
    phone: String(customer.phone || "").trim().slice(0, 80),
    address: String(customer.address || "").trim().slice(0, 300),
    preferred_date: String(customer.preferred_date || "").trim().slice(0, 80),
    preferred_time: String(customer.preferred_time || "").trim().slice(0, 80),
    note: String(customer.note || "").trim().slice(0, 300),
  };
}

function hasRequiredCustomerInfo(customer) {
  return Boolean(customer?.name && customer?.phone);
}

function customerDetailsPrompt(customer) {
  const missing = [];

  if (!customer?.name) {
    missing.push("your name");
  }

  if (!customer?.phone) {
    missing.push("your phone or WhatsApp number");
  }

  return `Before I place the order, please add ${missing.join(" and ")} in the customer details section, then send "yes" again.`;
}

function findAmbiguousProductChoice(message, products) {
  const keywordMatches = new Map();

  for (const product of products) {
    for (const keyword of getProductKeywords(product)) {
      if (!hasWord(message, keyword)) {
        continue;
      }

      if (!keywordMatches.has(keyword)) {
        keywordMatches.set(keyword, []);
      }

      keywordMatches.get(keyword).push(product);
    }
  }

  const ambiguousMatch = [...keywordMatches.entries()]
    .map(([keyword, matches]) => ({ keyword, matches }))
    .filter(match => {
      if (resolveUniqueOptionProduct(message, match.matches)) {
        return false;
      }

      const exactMatches = match.matches.filter(product =>
        productNameRegex(offeringDisplayName(product)).test(message) ||
        (product.option && productNameRegex(product.option).test(message))
      );

      if (exactMatches.length !== 1) {
        return true;
      }

      const sameNameMatches = match.matches.filter(product => product.name === exactMatches[0].name);
      return sameNameMatches.length > 1;
    })
    .find(match => match.matches.length > 1);

  return ambiguousMatch || null;
}

function resolveProductChoice(message, choices) {
  const optionMatch = resolveUniqueOptionProduct(message, choices);

  if (optionMatch) {
    return optionMatch;
  }

  const exactMatches = choices.filter(product =>
    productNameRegex(offeringDisplayName(product)).test(message) ||
    (product.option && productNameRegex(product.option).test(message))
  );

  if (exactMatches.length === 1) {
    return exactMatches[0];
  }

  const matchedChoices = choices.filter(product =>
    getProductKeywords(product).some(keyword => hasWord(message, keyword))
  );

  return matchedChoices.length === 1 ? matchedChoices[0] : null;
}

function findProductCategory(message, products) {
  const keywordMatches = new Map();

  for (const product of products) {
    for (const keyword of getProductKeywords(product)) {
      if (!hasWord(message, keyword)) {
        continue;
      }

      if (!keywordMatches.has(keyword)) {
        keywordMatches.set(keyword, []);
      }

      keywordMatches.get(keyword).push(product);
    }
  }

  return [...keywordMatches.entries()]
    .map(([keyword, matches]) => ({ keyword, matches }))
    .sort((a, b) => b.matches.length - a.matches.length || b.keyword.length - a.keyword.length)[0] || null;
}

function findDominantProductCategory(products) {
  const counts = new Map();

  for (const product of products) {
    for (const keyword of new Set(getProductKeywords(product))) {
      if (!counts.has(keyword)) {
        counts.set(keyword, []);
      }

      counts.get(keyword).push(product);
    }
  }

  return [...counts.entries()]
    .map(([keyword, matches]) => ({ keyword, matches }))
    .filter(match => match.matches.length > 1)
    .sort((a, b) => b.matches.length - a.matches.length || b.keyword.length - a.keyword.length)[0] || null;
}

function extractProduct(message, products) {
  const matches = products.filter(product => productSearchRegex(product).test(message));
  return matches.length === 1 ? matches[0] : null;
}

function removeProductTermsFromMessage(message, product) {
  return [...new Set([...getProductSearchTerms(product), ...getProductKeywords(product)])]
    .sort((a, b) => b.length - a.length)
    .reduce(
      (cleanedMessage, term) => cleanedMessage.replace(new RegExp(`\\b${escapeRegExp(term)}\\b`, "gi"), " "),
      message
    )
    .replace(/\s+/g, " ")
    .trim();
}

function extractQuantityWithoutProductTerms(message, product) {
  return extractQuantity(removeProductTermsFromMessage(message, product));
}

function extractOrderItems(message, products) {
  const normalizedMessage = message.toLowerCase();

  return products
    .map(product => {
      const productPattern = getProductNameVariants(product.name)
        .map(escapeRegExp)
        .join("|");

      if (!productSearchRegex(product).test(normalizedMessage)) {
        return null;
      }

      const quantityPattern = new RegExp(
        `(?:\\b(\\d+)\\b|\\b(one|two|three|four|five|six|seven|eight|nine|ten)\\b)\\s+(?:${productPattern})\\b`,
        "i"
      );
      const quantityMatch = normalizedMessage.match(quantityPattern);
      const parsedQuantity = quantityMatch
        ? extractQuantity(quantityMatch[0])
        : extractQuantityWithoutProductTerms(normalizedMessage, product);
      const quantity = orderQuantityForOffering(product, parsedQuantity);

      return {
        product_id: product._id,
        type: normalizedOfferingType(product.type),
        product: offeringDisplayName(product),
        quantity,
        unit_price: product.price,
        total_price: quantity ? product.price * quantity : null,
        duration: product.duration || "",
      };
    })
    .filter(Boolean);
}

function normalizeOrderItems(aiItems, fallbackProduct, fallbackQuantity, message, products) {
  const rawItems = Array.isArray(aiItems) && aiItems.length > 0
    ? aiItems
    : fallbackProduct
      ? [{ product: fallbackProduct, quantity: fallbackQuantity }]
      : extractOrderItems(message, products);

  return rawItems
    .map(item => {
      const productName = item.product || item.name;
      const selectedProduct = productName
        ? findProductByName(productName, products)
        : null;

      if (!selectedProduct) {
        return null;
      }

      const quantity = orderQuantityForOffering(selectedProduct, item.quantity);

      return {
        product_id: selectedProduct._id,
        type: normalizedOfferingType(selectedProduct.type),
        product: offeringDisplayName(selectedProduct),
        quantity,
        unit_price: selectedProduct.price,
        total_price: quantity ? selectedProduct.price * quantity : null,
        duration: selectedProduct.duration || "",
      };
    })
    .filter(Boolean);
}

function getOrderTotal(items) {
  return items.reduce((sum, item) => sum + item.total_price, 0);
}

function formatOrderItems(items, currency = "$") {
  return items
    .map(item => `- ${item.product}: ${item.quantity} x ${formatMoney(item.unit_price, currency)} = ${formatMoney(item.total_price, currency)}`)
    .join("\n");
}

function formatOrderSummary(order, currency = "$") {
  return `Order ${order.order_id}
Status: ${order.status}

${formatOrderItems(order.items, currency)}

Total: ${formatMoney(order.total_price, currency)}`;
}

function formatOrderList(orders, currency = "$") {
  return orders
    .map(order => `${order.order_id} - ${order.items.length} item${order.items.length === 1 ? "" : "s"} - ${formatMoney(order.total_price, currency)} - ${order.status}`)
    .join("\n");
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatCustomerForNotification(customer = {}) {
  const lines = [
    customer.name ? `Name: ${customer.name}` : "",
    customer.phone ? `Phone/WhatsApp: ${customer.phone}` : "",
    customer.address ? `Address/location: ${customer.address}` : "",
    customer.preferred_date ? `Preferred date: ${customer.preferred_date}` : "",
    customer.preferred_time ? `Preferred time: ${customer.preferred_time}` : "",
    customer.note ? `Note: ${customer.note}` : "",
  ].filter(Boolean);

  return lines.length ? lines.join("\n") : "No customer details provided.";
}

function formatOrderNotificationText({ business, order, currency, dashboardUrl }) {
  return `New order for ${business.name}

Order ID: ${order.order_id}
Status: ${order.status}

Customer:
${formatCustomerForNotification(order.customer)}

Items:
${formatOrderItems(order.items, currency)}

Total: ${formatMoney(order.total_price, currency)}

Dashboard:
${dashboardUrl}`;
}

function formatOrderNotificationHtml({ business, order, currency, dashboardUrl }) {
  const customerLines = formatCustomerForNotification(order.customer)
    .split("\n")
    .map(line => `<li>${escapeHtml(line)}</li>`)
    .join("");
  const itemLines = order.items
    .map(item => `<li>${escapeHtml(item.product)}: ${item.quantity} x ${escapeHtml(formatMoney(item.unit_price, currency))} = ${escapeHtml(formatMoney(item.total_price, currency))}</li>`)
    .join("");

  return `
    <div style="font-family:Arial,sans-serif;line-height:1.5;color:#142018">
      <h2>New order for ${escapeHtml(business.name)}</h2>
      <p><strong>Order ID:</strong> ${escapeHtml(order.order_id)}</p>
      <p><strong>Status:</strong> ${escapeHtml(order.status)}</p>
      <h3>Customer</h3>
      <ul>${customerLines}</ul>
      <h3>Items</h3>
      <ul>${itemLines}</ul>
      <p><strong>Total:</strong> ${escapeHtml(formatMoney(order.total_price, currency))}</p>
      <p><a href="${escapeHtml(dashboardUrl)}">Open dashboard</a></p>
    </div>
  `;
}

async function sendOrderNotificationEmail({ business, order, currency, req }) {
  const resendApiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || process.env.RESEND_FROM_EMAIL;
  const to = business.notification_email || business.email;

  if (!resendApiKey || !from || !to) {
    console.log("Order email notification skipped: missing RESEND_API_KEY, EMAIL_FROM, or recipient email.");
    return { sent: false, skipped: true };
  }

  const origin = `${req.protocol}://${req.get("host")}`;
  const dashboardUrl = `${origin}/admin`;
  const payload = {
    from,
    to,
    subject: `New order ${order.order_id} for ${business.name}`,
    text: formatOrderNotificationText({ business, order, currency, dashboardUrl }),
    html: formatOrderNotificationHtml({ business, order, currency, dashboardUrl }),
  };

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Resend email failed: ${response.status} ${body}`);
  }

  return { sent: true };
}

async function notifyBusinessOfOrder({ business, order, currency, req }) {
  try {
    return await sendOrderNotificationEmail({ business, order, currency, req });
  } catch (error) {
    console.error("Order email notification failed:", error.message);
    return { sent: false, error: error.message };
  }
}

async function generateOrderId(businessId) {
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const prefix = `SH-${today}-`;
  const counter = await OrderCounter.findOneAndUpdate(
    { businessId, date: today },
    { $inc: { sequence: 1 } },
    { upsert: true, returnDocument: "after", runValidators: true }
  ).lean();
  const sequence = String(counter.sequence).padStart(4, "0");

  return `${prefix}${sequence}`;
}

function extractOrderId(message) {
  const match = message.toUpperCase().match(/\bSH-\d{8}-\d{4}\b/);
  return match ? match[0] : null;
}

function isLastOrderRequest(message) {
  return /\b(show|check|view|get|see|track)\b.*\b(my\s+)?(last|latest|recent)\s+order\b/.test(message) ||
    /\b(my\s+)?(last|latest|recent)\s+order\b/.test(message);
}

function isAllOrdersRequest(message) {
  return /\b(show|check|view|get|see|list)\b.*\b(my\s+)?(all\s+)?orders\b/.test(message) ||
    /\b(my\s+)?all\s+orders\b/.test(message) ||
    /\border\s+history\b/.test(message);
}

function addOrUpdateOrderItem(order, product, quantity) {
  const displayName = offeringDisplayName(product);
  const existingItem = order.items.find(item => item.product_id.toString() === product._id.toString());

  if (existingItem) {
    existingItem.quantity = quantity;
    existingItem.total_price = quantity * existingItem.unit_price;
  } else {
    order.items.push({
      product_id: product._id,
      type: normalizedOfferingType(product.type),
      product: displayName,
      quantity,
      unit_price: product.price,
      total_price: quantity * product.price,
      duration: product.duration || "",
    });
  }

  order.total_price = getOrderTotal(order.items);
}

async function checkStockAvailability(items, businessId) {
  for (const item of items) {
    const product = await Product.findOne({
      _id: item.product_id,
      businessId,
      active: true,
    }).lean();

    if (!product) {
      return {
        ok: false,
        status: 404,
        item,
        product: null,
        reply: `${item.product} is no longer available.`,
      };
    }

    if (isServiceOffering(product)) {
      continue;
    }

    if (item.quantity > product.stock_quantity) {
      return {
        ok: false,
        status: 400,
        item,
        product,
        reply: `Sorry, we only have ${product.stock_quantity} ${product.name} left.`,
      };
    }
  }

  return { ok: true };
}

function removeOrderItem(order, productName) {
  if (!order?.items) {
    return;
  }

  order.items = order.items.filter(item => item.product !== productName);
  order.total_price = getOrderTotal(order.items);
}

function clearPendingOrderIfEmpty(memory) {
  if (memory.pendingOrder?.items?.length === 0) {
    memory.pendingOrder = null;
    memory.awaitingProductChoice = null;
  }
}

function clearUnavailablePendingItem(memory, stockCheck) {
  if (!stockCheck?.item?.product) {
    return;
  }

  removeOrderItem(memory.pendingOrder, stockCheck.item.product);
  if (memory.lastProduct === stockCheck.item.product) {
    memory.lastProduct = null;
  }
  clearPendingOrderIfEmpty(memory);
}

function removeZeroStockPendingItems(memory, products) {
  if (!memory.pendingOrder?.items?.length) {
    return [];
  }

  const removedItems = [];

  for (const item of [...memory.pendingOrder.items]) {
    const product = products.find(candidate => candidate._id.toString() === item.product_id.toString()) ||
      findProductByName(item.product, products);

    if (!product || (!isServiceOffering(product) && product.stock_quantity <= 0)) {
      removeOrderItem(memory.pendingOrder, item.product);
      removedItems.push(item.product);
    }
  }

  if (removedItems.includes(memory.lastProduct)) {
    memory.lastProduct = null;
  }

  clearPendingOrderIfEmpty(memory);
  return removedItems;
}

async function reduceStock(items, businessId) {
  const reducedItems = [];

  for (const item of items) {
    if (item.type === "service") {
      continue;
    }

    const result = await Product.updateOne(
      {
        _id: item.product_id,
        businessId,
        stock_quantity: { $gte: item.quantity },
      },
      { $inc: { stock_quantity: -item.quantity } }
    );

    if (result.modifiedCount !== 1) {
      await restoreStock(reducedItems, businessId);

      const error = new Error(`Sorry, ${item.product} does not have enough stock left.`);
      error.status = 400;
      error.reply = `Sorry, ${item.product} does not have enough stock left.`;
      throw error;
    }

    reducedItems.push(item);
  }
}

async function restoreStock(items, businessId) {
  for (const item of items) {
    if (item.type === "service") {
      continue;
    }

    await Product.updateOne(
      { _id: item.product_id, businessId },
      { $inc: { stock_quantity: item.quantity } }
    );
  }
}

function getPendingOrderForPrompt(memory) {
  if (!memory.pendingOrder) {
    return null;
  }

  return {
    items: memory.pendingOrder.items.map(item => ({
      product: item.product,
      quantity: item.quantity,
      unit_price: item.unit_price,
      total_price: item.total_price,
    })),
    total_price: memory.pendingOrder.total_price,
    awaitingProductChoice: memory.awaitingProductChoice || null,
    lastProduct: memory.lastProduct || null,
  };
}

async function getAiIntent({ message, business, productsForPrompt, memory }) {
  const routerPrompt = `
You are the intent router for a business chat assistant.

Your job is to understand what the customer means. Do not execute actions.
Return JSON only.

Business:
${JSON.stringify({
  name: business.name,
  tone: business.tone,
  currency: business.currency,
  description: business.description || "",
  contact_info: business.contact_info || "",
  ai_personality: business.ai_personality || "",
}, null, 2)}

Products:
${JSON.stringify(productsForPrompt, null, 2)}

Conversation state:
${JSON.stringify(getPendingOrderForPrompt(memory), null, 2)}

Allowed intents:
- greeting: simple greeting or social check-in.
- business_chat: customer asks a conversational question about the business, products, recommendations, or availability.
- browse_products: customer asks what products/items are available.
- ask_stock: customer asks what is in stock, whether that is all, or how many are available.
- ask_price: customer asks price/cost.
- start_order: customer wants to buy/order a product.
- change_quantity: customer changes quantity to a specific number.
- set_quantity_to_available_stock: customer wants all available stock of a product.
- add_product: customer wants to add another product to pending order.
- confirm_order: customer confirms a pending order.
- cancel_order: customer cancels a pending order.
- unknown: unclear.

Rules:
- Use only products from the product list.
- If a product is implied by the pending order or lastProduct, include it.
- If the customer says "all the [product] you have", use set_quantity_to_available_stock.
- If the customer asks "is that all you have in stock?", use ask_stock or browse_products, not change_quantity.
- If the customer is just being social ("how are you", "hey"), use greeting even when there is a pending order.
- Keep reply short and business-focused.

JSON shape:
{
  "intent": "greeting" | "business_chat" | "browse_products" | "ask_stock" | "ask_price" | "start_order" | "change_quantity" | "set_quantity_to_available_stock" | "add_product" | "confirm_order" | "cancel_order" | "unknown",
  "product": string | null,
  "quantity": number | null,
  "reply": string
}
`;

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: routerPrompt },
      { role: "user", content: message },
    ],
  });

  return JSON.parse(response.choices[0].message.content);
}

async function getAiCompletedOrderFollowup({ message, business, order, currency }) {
  const followupPrompt = `
You are helping a customer after they just placed an order.

Your task:
1. Decide if the customer's message is about the completed order.
2. If yes, answer naturally using the order and business context.
3. If no, return is_followup false and an empty reply.

Classify as follow-up if the customer asks about:
- delivery, pickup, arrival time, ETA, when to expect it
- order status, order ID, what happens next
- changing/cancelling after placing the order
- payment or contact about the placed order
- appreciation/closing messages like thanks or thank you

Do NOT classify as follow-up if the customer:
- wants to start a new order
- asks what products are available
- asks price/stock for products
- changes topic to normal product browsing
- sends a fresh greeting that is not about the order

Important:
- Do not create, cancel, or modify orders.
- Do not promise an exact delivery/pickup time unless the business context clearly says one.
- If timing is unknown, say the business will contact them using their provided details.
- If the message is appreciation/thanks after the order, mention that the order is confirmed or received and include the order ID.
- Keep the reply short and helpful.

Business:
${JSON.stringify({
  name: business.name,
  tone: business.tone,
  currency: business.currency,
  description: business.description || "",
  contact_info: business.contact_info || "",
  ai_personality: business.ai_personality || "",
}, null, 2)}

Completed order:
${JSON.stringify({
  order_id: order.order_id,
  status: order.status,
  total_price: order.total_price,
  currency,
  items: order.items,
  customer: order.customer || {},
}, null, 2)}

Return JSON only:
{
  "is_followup": boolean,
  "reply": string
}
`;

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: followupPrompt },
      { role: "user", content: message },
    ],
  });

  return JSON.parse(response.choices[0].message.content);
}

app.post("/businesses", async (req, res) => {
  try {
    const { businessId, name, email, password, currency, tone, description, contact_info, notification_email, ai_personality } = req.body;

    if (!businessId || !name || !email) {
      return res.status(400).json({ error: "businessId, name, and email are required." });
    }

    const normalizedBusinessId = businessId.trim();
    const normalizedEmail = email.toLowerCase().trim();
    const existingBusiness = await Business.findOne({ businessId: normalizedBusinessId }).select("+password_hash");
    const update = {
      businessId: normalizedBusinessId,
      email: normalizedEmail,
      name: name.trim(),
      currency: currency || "$",
      tone: tone || "friendly",
      description: description || "",
      contact_info: contact_info || "",
      notification_email: notification_email ? String(notification_email).toLowerCase().trim() : normalizedEmail,
      ai_personality: ai_personality || "",
    };

    if (existingBusiness) {
      const token = getBearerToken(req);
      const payload = token ? verifyToken(token) : null;

      if (payload?.businessId !== existingBusiness.businessId) {
        return res.status(403).json({ error: "Login is required to update this business profile." });
      }

      if (password) {
        update.password_hash = hashPassword(password);
      }

      const business = await Business.findOneAndUpdate(
        { businessId: normalizedBusinessId },
        update,
        { returnDocument: "after", runValidators: true }
      );

      return res.json({ business: publicBusinessProfile(business) });
    }

    if (!password || password.length < 6) {
      return res.status(400).json({ error: "password must be at least 6 characters." });
    }

    update.password_hash = hashPassword(password);

    const business = await Business.create(update);
    const token = signToken({
      businessId: business.businessId,
      exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
    });

    return res.status(201).json({ business: publicBusinessProfile(business), token });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: "Business ID or email already exists." });
    }

    return res.status(500).json({ error: "Could not save business profile." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required." });
    }

    const business = await Business.findOne({ email: email.toLowerCase().trim() }).select("+password_hash");

    if (!business || !verifyPassword(password, business.password_hash)) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = signToken({
      businessId: business.businessId,
      exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
    });

    return res.json({ token, business: publicBusinessProfile(business) });
  } catch (error) {
    return res.status(500).json({ error: "Could not log in." });
  }
});

app.get("/businesses/:businessId", requireAuth, async (req, res) => {
  try {
    if (!requireMatchingBusiness(req, res, req.params.businessId)) {
      return;
    }

    return res.json({ business: publicBusinessProfile(req.business) });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch business profile." });
  }
});

app.get("/public/businesses/:businessId", async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();

    if (!business) {
      return res.status(404).json({ error: "Business not found." });
    }

    return res.json({
      business: {
        businessId: business.businessId,
        name: business.name,
        currency: business.currency,
        tone: business.tone,
        description: business.description,
        contact_info: business.contact_info,
        ai_personality: business.ai_personality,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch business profile." });
  }
});

app.get("/public/products/:businessId", async (req, res) => {
  try {
    const products = await Product.find({
      businessId: req.params.businessId,
      active: true,
    })
      .select("type name option price stock_quantity duration requires_booking_time")
      .sort({ type: 1, name: 1, option: 1 })
      .lean();

    return res.json({
      products: products.map(product => ({
        type: normalizedOfferingType(product.type),
        name: product.name,
        option: product.option || "",
        display_name: offeringDisplayName(product),
        price: product.price,
        stock_quantity: product.stock_quantity,
        duration: product.duration || "",
        requires_booking_time: Boolean(product.requires_booking_time),
      })),
    });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch public products." });
  }
});

async function loadPublicBusiness(req, res, next) {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();

    if (!business) {
      return res.status(404).json({
        reply: "Business not found.",
        order: null,
      });
    }

    req.business = business;
    req.businessId = business.businessId;
    req.isPublicChat = true;
    return next();
  } catch (error) {
    return res.status(500).json({
      reply: "Could not load this business.",
      order: null,
    });
  }
}

app.post("/products", requireAuth, async (req, res) => {
  try {
    const { name, option, price, stock_quantity, aliases, type, duration, requires_booking_time } = req.body;
    const businessId = req.businessId;

    if (!requireMatchingBusiness(req, res, req.body.businessId || businessId)) {
      return;
    }

    if (!name || price === undefined) {
      return res.status(400).json({
        error: "name and price are required.",
      });
    }

    const numericPrice = Number(price);

    if (!Number.isFinite(numericPrice) || numericPrice < 0) {
      return res.status(400).json({
        error: "price must be a valid positive number.",
      });
    }

    const normalizedName = name.toLowerCase().trim();
    const normalizedOption = normalizeOfferingOption(option);
    const offeringType = normalizedOfferingType(type);
    const numericStock = stock_quantity === undefined ? null : Number(stock_quantity);
    const duplicateNameExists = await Product.exists({
      businessId,
      name: normalizedName,
      active: true,
    });

    if (duplicateNameExists && !normalizedOption) {
      return res.status(400).json({
        error: "This name already exists. Add an Option / Package, like 'short', 'medium', or 'long', so customers can choose correctly.",
      });
    }

    if (offeringType === "product" && numericStock !== null && (!Number.isInteger(numericStock) || numericStock < 0)) {
      return res.status(400).json({
        error: "stock_quantity must be a valid whole number.",
      });
    }

    const update = {
      businessId,
      type: offeringType,
      name: normalizedName,
      option: normalizedOption,
      aliases: normalizeAliases(aliases),
      price: numericPrice,
      duration: duration || "",
      requires_booking_time: Boolean(requires_booking_time),
      active: true,
    };

    if (offeringType === "service") {
      update.stock_quantity = 0;
    } else if (numericStock !== null) {
      update.stock_quantity = numericStock;
    }

    const product = await Product.create(update);

    return res.status(201).json({ product });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        error: "This name and option already exists. Use a different option/package name, or edit the existing one.",
      });
    }

    return res.status(500).json({ error: "Could not save product." });
  }
});

app.get("/products/:businessId", requireAuth, async (req, res) => {
  try {
    if (!requireMatchingBusiness(req, res, req.params.businessId)) {
      return;
    }

    const products = await Product.find({
      businessId: req.businessId,
      active: true,
    })
      .sort({ name: 1 })
      .lean();

    return res.json({ products });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch products." });
  }
});

// 🚀 MAIN ENDPOINT
app.put("/products/:id", requireAuth, async (req, res) => {
  try {
    const { name, option, price, stock_quantity, aliases, active, type, duration, requires_booking_time } = req.body;
    const update = {};
    const existingProduct = await Product.findById(req.params.id).lean();

    if (!existingProduct) {
      return res.status(404).json({ error: "Product not found." });
    }

    if (!requireMatchingBusiness(req, res, existingProduct.businessId)) {
      return;
    }

    if (name !== undefined) {
      update.name = String(name).toLowerCase().trim();
    }

    if (option !== undefined) {
      update.option = normalizeOfferingOption(option);
    }

    if (aliases !== undefined) {
      update.aliases = normalizeAliases(aliases);
    }

    if (type !== undefined) {
      update.type = normalizedOfferingType(type);
    }

    if (price !== undefined) {
      const numericPrice = Number(price);

      if (!Number.isFinite(numericPrice) || numericPrice < 0) {
        return res.status(400).json({ error: "price must be a valid positive number." });
      }

      update.price = numericPrice;
    }

    if (stock_quantity !== undefined) {
      const numericStock = Number(stock_quantity);

      if (!Number.isInteger(numericStock) || numericStock < 0) {
        return res.status(400).json({ error: "stock_quantity must be a valid whole number." });
      }

      update.stock_quantity = numericStock;
    }

    if (duration !== undefined) {
      update.duration = String(duration || "").trim();
    }

    if (requires_booking_time !== undefined) {
      update.requires_booking_time = Boolean(requires_booking_time);
    }

    const nextName = update.name ?? existingProduct.name;
    const nextOption = update.option ?? normalizeOfferingOption(existingProduct.option);
    const duplicateNameExists = await Product.exists({
      _id: { $ne: existingProduct._id },
      businessId: existingProduct.businessId,
      name: nextName,
      active: true,
    });

    if (duplicateNameExists && !nextOption) {
      return res.status(400).json({
        error: "This name is shared by more than one offering. Add an Option / Package so customers can choose correctly.",
      });
    }

    if (update.type === "service") {
      update.stock_quantity = 0;
    }

    if (active !== undefined) {
      update.active = Boolean(active);
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      update,
      { returnDocument: "after", runValidators: true }
    );

    if (!product) {
      return res.status(404).json({ error: "Product not found." });
    }

    return res.json({ product });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        error: "This name and option already exists. Use a different option/package name.",
      });
    }

    return res.status(500).json({ error: "Could not update product." });
  }
});

app.delete("/products/:id", requireAuth, async (req, res) => {
  try {
    const existingProduct = await Product.findById(req.params.id).lean();

    if (!existingProduct) {
      return res.status(404).json({ error: "Product not found." });
    }

    if (!requireMatchingBusiness(req, res, existingProduct.businessId)) {
      return;
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { active: false },
      { returnDocument: "after" }
    );

    if (!product) {
      return res.status(404).json({ error: "Product not found." });
    }

    return res.json({ product });
  } catch (error) {
    return res.status(500).json({ error: "Could not delete product." });
  }
});

app.get("/orders/:businessId", requireAuth, async (req, res) => {
  try {
    if (!requireMatchingBusiness(req, res, req.params.businessId)) {
      return;
    }

    const orders = await Order.find({ businessId: req.businessId })
      .sort({ created_at: -1 })
      .lean();

    return res.json({ orders });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch orders." });
  }
});

app.patch("/orders/:orderId/status", requireAuth, async (req, res) => {
  try {
    const allowedStatuses = ["placed", "processing", "delivered"];
    const { status } = req.body;

    if (!requireMatchingBusiness(req, res, req.body.businessId || req.businessId)) {
      return;
    }

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        error: `status must be one of: ${allowedStatuses.join(", ")}.`,
      });
    }

    const order = await Order.findOneAndUpdate(
      { order_id: req.params.orderId, businessId: req.businessId },
      { status },
      { returnDocument: "after", runValidators: true }
    );

    if (!order) {
      return res.status(404).json({ error: "Order not found." });
    }

    return res.json({ order });
  } catch (error) {
    return res.status(500).json({ error: "Could not update order status." });
  }
});

async function chatHandler(req, res) {
  try {
    const rawMessage = req.body.message;
    const userId = req.body.userId || "default";
    const businessId = req.businessId;

    if (!requireMatchingBusiness(req, res, req.body.businessId || businessId)) {
      return;
    }

    if (!rawMessage) {
      return res.status(400).json({
        reply: "message is required.",
        order: null,
      });
    }

    const message = rawMessage.toLowerCase();
    const business = req.business;
    const currency = business.currency || "$";
    const customer = sanitizeCustomerInfo(req.body.customer);

    if (!userMemory[userId]) {
      userMemory[userId] = {};
    }

    if (!userMemory[userId][businessId]) {
      userMemory[userId][businessId] = {};
    }

    const memory = userMemory[userId][businessId];
    const requestedOrderId = extractOrderId(message);

    if (requestedOrderId) {
      const order = await Order.findOne({ order_id: requestedOrderId, businessId, userId }).lean();

      if (!order) {
        return res.json({
          reply: `I couldn't find order ${requestedOrderId} for this customer and business. Please check the order ID and try again.`,
          order: null,
        });
      }

      return res.json({
        reply: formatOrderSummary(order, currency),
        order,
      });
    }

    if (isLastOrderRequest(message)) {
      const order = await Order.findOne({ businessId, userId })
        .sort({ created_at: -1 })
        .lean();

      if (!order) {
        return res.json({
          reply: "You don't have any orders yet.",
          order: null,
        });
      }

      return res.json({
        reply: `Here is your last order:\n\n${formatOrderSummary(order, currency)}`,
        order,
      });
    }

    if (isAllOrdersRequest(message)) {
      const orders = await Order.find({ businessId, userId })
        .sort({ created_at: -1 })
        .limit(10)
        .lean();

      if (orders.length === 0) {
        return res.json({
          reply: "You don't have any orders yet.",
          orders: [],
        });
      }

      return res.json({
        reply: `Here are your orders:\n\n${formatOrderList(orders, currency)}`,
        orders,
      });
    }

    if (!memory.pendingOrder && memory.lastCompletedOrder) {
      try {
        const followup = await getAiCompletedOrderFollowup({
          message,
          business,
          order: memory.lastCompletedOrder,
          currency,
        });

        if (followup?.is_followup && followup.reply) {
          return res.json({
            reply: followup.reply,
            order: memory.lastCompletedOrder,
          });
        }
      } catch (error) {
        console.error("Completed order follow-up error:", error.message);
      }
    }

    const products = await Product.find({ businessId, active: true }).lean();
    const validProductNames = products.map(p => offeringDisplayName(p).toLowerCase());

    if (products.length === 0) {
      return res.json({
        reply: "This business does not have any products yet.",
        order: null,
      });
    }

    removeZeroStockPendingItems(memory, products);

    const productsForPrompt = products.map(product => ({
      type: normalizedOfferingType(product.type),
      name: product.name,
      option: product.option || "",
      display_name: offeringDisplayName(product),
      aliases: product.aliases || [],
      price: product.price,
      stock_quantity: product.stock_quantity,
      duration: product.duration || "",
      requires_booking_time: Boolean(product.requires_booking_time),
    }));

    const pendingOrderReadyToConfirm = memory.pendingOrder?.items?.length > 0 &&
      memory.pendingOrder.items.every(item => item.quantity && item.quantity > 0);

    if (pendingOrderReadyToConfirm && isYes(message)) {
      if (req.isPublicChat && !hasRequiredCustomerInfo(customer)) {
        return res.json({
          reply: customerDetailsPrompt(customer),
          order: null,
        });
      }

      const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

      if (!stockCheck.ok) {
        clearUnavailablePendingItem(memory, stockCheck);
        return res.status(stockCheck.status).json({
          reply: `${stockCheck.reply} I've removed it from your pending order so you can choose another product.`,
          order: null,
        });
      }

      const order = {
        order_id: await generateOrderId(businessId),
        userId,
        businessId,
        customer,
        ...memory.pendingOrder,
      };

      let stockReduced = false;
      let savedOrder;

      try {
        await reduceStock(order.items, businessId);
        stockReduced = true;
        savedOrder = await Order.create(order);
      } catch (error) {
        if (stockReduced) {
          await restoreStock(order.items, businessId);
        }

        if (error.reply) {
          return res.status(error.status).json({
            reply: error.reply,
            order: null,
          });
        }

        throw error;
      }

      const orderData = savedOrder.toObject();
      memory.pendingOrder = null;
      memory.awaitingProductChoice = null;
      memory.lastCompletedOrder = orderData;
      memory.lastIntent = "order_completed";
      notifyBusinessOfOrder({ business, order: orderData, currency, req });

      return res.json({
        reply: `✅ Your order has been placed.\n\nOrder ID: ${orderData.order_id}\n\n${formatOrderItems(orderData.items, currency)}\n\nTotal: ${formatMoney(orderData.total_price, currency)}`,
        order: orderData,
      });
    }

    if (memory.pendingOrder && isNo(message)) {
      memory.pendingOrder = null;
      memory.awaitingProductChoice = null;

      return res.json({
        reply: "No problem 👍 Your order has been cancelled.",
        order: null,
      });
    }

    const ambiguousProductChoice = findAmbiguousProductChoice(message, products);
    const productFromMessage = extractProduct(message, products);
    const productCategory = findProductCategory(message, products);
    let aiIntent = null;

    if (!memory.pendingOrder && memory.lastCatalog?.length && isCatalogConfirmationFollowup(message)) {
      const catalogProducts = products.filter(product => memory.lastCatalog.includes(offeringDisplayName(product)));

      return res.json({
        reply: `Yes. This is the current list I have for ${business.name}:\n\n${formatProductCatalog(catalogProducts.length ? catalogProducts : products, currency)}\n\nIf something is missing, the business owner may need to add it in the admin dashboard.`,
        order: null,
      });
    }

    if (!memory.pendingOrder && memory.awaitingBusinessFollowup?.action === "show_catalog" && isYes(message)) {
      memory.awaitingBusinessFollowup = null;
      memory.lastCatalog = products.map(product => offeringDisplayName(product));
      memory.lastIntent = "browse_products";

      return res.json({
        reply: `Of course. Here is what we currently have:\n\n${formatProductCatalog(products, currency)}`,
        order: null,
      });
    }

    try {
      aiIntent = await getAiIntent({ message, business, productsForPrompt, memory });
    } catch (error) {
      console.error("AI intent router error:", error.message);
    }

    const aiProduct = aiIntent?.product ? findProductByName(aiIntent.product, products) : null;
    const aiQuantity = Number.isInteger(Number(aiIntent?.quantity)) && Number(aiIntent.quantity) > 0
      ? Number(aiIntent.quantity)
      : null;

    if (aiIntent?.intent === "greeting" || aiIntent?.intent === "business_chat") {
      const reply = aiIntent.reply || `Hey! How can I help you with ${business.name} today?`;
      memory.awaitingBusinessFollowup = buildBusinessChatFollowup(reply, products);
      memory.lastIntent = memory.awaitingBusinessFollowup ? "business_chat_offer" : "chat";

      return res.json({
        reply,
        order: null,
      });
    }

    if (aiIntent?.intent === "browse_products" || aiIntent?.intent === "ask_stock") {
      const matchingProducts = isBroadCatalogRequest(message)
        ? products
        : ((aiProduct ? [aiProduct] : productCategory?.matches) || products);
      const pendingNote = memory.pendingOrder?.items?.length
        ? `\n\nYour pending order is still here:\n${formatOrderItems(memory.pendingOrder.items, currency)}\n\nTotal: ${formatMoney(memory.pendingOrder.total_price, currency)}`
        : "";

      if (matchingProducts.length === 1) {
        memory.lastProduct = offeringDisplayName(matchingProducts[0]);
      }

      memory.lastCatalog = matchingProducts.map(product => offeringDisplayName(product));
      memory.lastIntent = aiIntent.intent;

      return res.json({
        reply: `Here is what we currently have:\n\n${formatProductCatalog(matchingProducts, currency)}${pendingNote}`,
        order: null,
      });
    }

    if (aiIntent?.intent === "ask_price") {
      const selectedProduct = aiProduct || productFromMessage ||
        (memory.lastProduct ? findProductByName(memory.lastProduct, products) : null);

      if (selectedProduct) {
        memory.lastProduct = offeringDisplayName(selectedProduct);
        memory.lastIntent = "price_check";

        return res.json({
          reply: `${offeringDisplayName(selectedProduct)} is ${formatMoney(selectedProduct.price, currency)}. Would you like to order it?`,
          order: null,
        });
      }
    }

    if (aiIntent?.intent === "set_quantity_to_available_stock") {
      const selectedProduct = aiProduct || productFromMessage ||
        (memory.lastProduct ? findProductByName(memory.lastProduct, products) : null);

      if (selectedProduct) {
        if (selectedProduct.stock_quantity <= 0) {
          return res.json({
            reply: `Sorry, ${offeringDisplayName(selectedProduct)} is currently out of stock.`,
            order: null,
          });
        }

        const previousOrder = memory.pendingOrder
          ? JSON.parse(JSON.stringify(memory.pendingOrder))
          : null;

        if (!memory.pendingOrder) {
          memory.pendingOrder = {
            items: [],
            total_price: 0,
          };
        }

        addOrUpdateOrderItem(memory.pendingOrder, selectedProduct, selectedProduct.stock_quantity);
        const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

        if (!stockCheck.ok) {
          if (previousOrder) {
            memory.pendingOrder = previousOrder;
          }
          return res.status(stockCheck.status).json({
            reply: stockCheck.reply,
            order: null,
          });
        }

        memory.lastProduct = offeringDisplayName(selectedProduct);
        memory.awaitingProductChoice = null;
        memory.lastIntent = "order";

        return res.json({
          reply: `Got it. I've set ${offeringDisplayName(selectedProduct)} to all available stock (${selectedProduct.stock_quantity}).\n\n🛒 Order Summary:\n${formatOrderItems(memory.pendingOrder.items, currency)}\n\nTotal: ${formatMoney(memory.pendingOrder.total_price, currency)}\n\n👉 Would you like to proceed with the purchase? (yes/no)`,
          order: null,
        });
      }
    }

    if (aiIntent?.intent === "change_quantity" && memory.pendingOrder && aiQuantity && (aiProduct || memory.lastProduct)) {
      const selectedProduct = aiProduct || findProductByName(memory.lastProduct, products);
      const existingItem = selectedProduct
        ? memory.pendingOrder.items.find(item => item.product_id.toString() === selectedProduct._id.toString())
        : null;

      if (selectedProduct) {
        const previousOrder = JSON.parse(JSON.stringify(memory.pendingOrder));
        addOrUpdateOrderItem(memory.pendingOrder, selectedProduct, aiQuantity);
        memory.pendingOrder.total_price = getOrderTotal(memory.pendingOrder.items);
        const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

        if (!stockCheck.ok) {
          memory.pendingOrder = previousOrder;
          return res.status(stockCheck.status).json({
            reply: stockCheck.reply,
            order: null,
          });
        }

        memory.lastProduct = offeringDisplayName(selectedProduct);
        memory.awaitingProductChoice = null;

        return res.json({
          reply: `${existingItem ? "Got it. I've updated your order" : "Got it. I've added that to your order"}:\n\n🛒 Order Summary:\n${formatOrderItems(memory.pendingOrder.items, currency)}\n\nTotal: ${formatMoney(memory.pendingOrder.total_price, currency)}\n\n👉 Would you like to proceed with the purchase? (yes/no)`,
          order: null,
        });
      }
    }

    if (!memory.pendingOrder && memory.lastIntent === "price_check" && isYes(message) && memory.lastProduct) {
      const selectedProduct = findProductByName(memory.lastProduct, products);

      if (selectedProduct) {
        memory.pendingOrder = {
          items: [{
            product_id: selectedProduct._id,
            type: normalizedOfferingType(selectedProduct.type),
            product: offeringDisplayName(selectedProduct),
            quantity: null,
            unit_price: selectedProduct.price,
            total_price: null,
            duration: selectedProduct.duration || "",
          }],
          total_price: 0,
        };
        memory.lastIntent = "order";

        return res.json({
          reply: `Nice choice! 👌\n\nHow many ${offeringDisplayName(selectedProduct)} would you like?`,
          order: null,
        });
      }
    }

    if (!memory.pendingOrder && isGreetingOnly(message)) {
      memory.lastIntent = "chat";

      return res.json({
        reply: `Hey! How can I help you with ${business.name} today?`,
        order: null,
      });
    }

    if (!memory.pendingOrder && memory.awaitingProductChoice?.action === "price_check") {
      const pendingChoices = memory.awaitingProductChoice.choices
        ? products.filter(product => memory.awaitingProductChoice.choices.includes(offeringDisplayName(product)))
        : products;
      const selectedProduct = resolveProductChoice(message, pendingChoices) || productFromMessage;

      if (selectedProduct) {
        memory.lastProduct = offeringDisplayName(selectedProduct);
        memory.lastIntent = "price_check";
        memory.awaitingProductChoice = null;

        return res.json({
          reply: `${offeringDisplayName(selectedProduct)} is ${formatMoney(selectedProduct.price, currency)}. Would you like to order it?`,
          order: null,
        });
      }

      return res.json({
        reply: `Sure. Which ${memory.awaitingProductChoice.keyword || "product"} would you like: ${formatProductChoices(pendingChoices, currency)}?`,
        order: null,
      });
    }

    if (!memory.pendingOrder && isBrowseRequest(message)) {
      const matchingProducts = isBroadCatalogRequest(message)
        ? products
        : productCategory?.matches?.length > 0
        ? productCategory.matches
        : products;

      if (productCategory?.keyword) {
        memory.lastCategory = productCategory.keyword;
      }

      memory.lastCatalog = matchingProducts.map(product => offeringDisplayName(product));
      memory.lastIntent = "browse";

      return res.json({
        reply: `We have:\n\n${formatProductCatalog(matchingProducts, currency)}`,
        order: null,
      });
    }

    if (!memory.pendingOrder && isPriceRequest(message)) {
      const selectedProduct = productFromMessage ||
        (memory.lastProduct ? findProductByName(memory.lastProduct, products) : null);

      if (selectedProduct) {
        memory.lastProduct = offeringDisplayName(selectedProduct);
        memory.lastIntent = "price_check";

        return res.json({
          reply: `${offeringDisplayName(selectedProduct)} is ${formatMoney(selectedProduct.price, currency)}. Would you like to order it?`,
          order: null,
        });
      }

      const category = productCategory || findDominantProductCategory(products);

      if (category) {
        memory.lastCategory = category.keyword;
        memory.lastIntent = "price_check";
        memory.awaitingProductChoice = {
          action: "price_check",
          keyword: category.keyword,
          choices: category.matches.map(product => offeringDisplayName(product)),
        };

        return res.json({
          reply: `Sure. Which ${category.keyword} would you like: ${formatProductChoices(category.matches, currency)}?`,
          order: null,
        });
      }

      memory.lastIntent = "price_check";

      return res.json({
        reply: "Which product would you like the price for?",
        order: null,
      });
    }

    if (!memory.pendingOrder && isOrderRequest(message) && ambiguousProductChoice) {
      const ambiguousProductIds = new Set(
        ambiguousProductChoice.matches.map(product => product._id.toString())
      );
      const orderItems = extractOrderItems(message, products).filter(
        item => item.quantity && !ambiguousProductIds.has(item.product_id.toString())
      );
      const requestedQty = extractQuantity(message);
      const stockCheck = await checkStockAvailability(orderItems, businessId);

      if (!stockCheck.ok) {
        return res.status(stockCheck.status).json({
          reply: stockCheck.reply,
          order: null,
        });
      }

      memory.pendingOrder = {
        items: orderItems,
        total_price: getOrderTotal(orderItems),
      };
      memory.awaitingProductChoice = {
        action: "order",
        keyword: ambiguousProductChoice.keyword,
        quantity: requestedQty,
        choices: ambiguousProductChoice.matches.map(product => offeringDisplayName(product)),
      };

      const summary = orderItems.length > 0
        ? `\n\nCurrent order:\n${formatOrderItems(orderItems, currency)}\n\nTotal: ${formatMoney(memory.pendingOrder.total_price, currency)}`
        : "";

      return res.json({
        reply: `Sure. Which ${ambiguousProductChoice.keyword} would you like: ${formatProductChoices(ambiguousProductChoice.matches, currency)}?${summary}`,
        order: null,
      });
    }

    // =============================
    // 🧠 STEP 1: HANDLE PENDING ORDER (UPGRADED)
    // =============================
    if (memory.pendingOrder) {

      const newQty = extractQuantity(message);
      const newProduct = extractProduct(message, products);
      const pendingChoices = memory.awaitingProductChoice?.choices
        ? products.filter(product => memory.awaitingProductChoice.choices.includes(offeringDisplayName(product)))
        : [];
      const selectedProductChoice = pendingChoices.length > 0
        ? resolveProductChoice(message, pendingChoices)
        : null;
      const pendingAmbiguousChoice = findAmbiguousProductChoice(message, products);

      if (memory.awaitingProductChoice) {
        const selectedChoiceQuantity = selectedProductChoice
          ? extractQuantityWithoutProductTerms(message, selectedProductChoice)
          : null;

        if (!selectedProductChoice && newQty) {
          memory.awaitingProductChoice.quantity = newQty;
        }

        if (selectedProductChoice && selectedChoiceQuantity) {
          memory.awaitingProductChoice.quantity = selectedChoiceQuantity;
        }

        if (newQty && memory.awaitingProductChoice.product) {
          const previousOrder = JSON.parse(JSON.stringify(memory.pendingOrder));
          const selectedProduct = products.find(
            p => p.name === memory.awaitingProductChoice.product
          );

          addOrUpdateOrderItem(memory.pendingOrder, selectedProduct, newQty);
          const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

          if (!stockCheck.ok) {
            memory.pendingOrder = previousOrder;
            return res.status(stockCheck.status).json({
              reply: stockCheck.reply,
              order: null,
            });
          }

          memory.lastProduct = offeringDisplayName(selectedProduct);
          memory.awaitingProductChoice = null;

          return res.json({
            reply: `✅ Got it! I've updated your order:

🛒 New Order Summary:
${formatOrderItems(memory.pendingOrder.items, currency)}

Total: ${formatMoney(memory.pendingOrder.total_price, currency)}

👉 Would you like to proceed with the purchase? (yes/no)`,
            order: null,
          });
        }

        if (selectedProductChoice) {
          const qty = memory.awaitingProductChoice.quantity;

          if (!qty) {
            memory.lastProduct = offeringDisplayName(selectedProductChoice);
            memory.awaitingProductChoice.product = offeringDisplayName(selectedProductChoice);

            return res.json({
              reply: `Nice choice! 👌\n\nHow many ${offeringDisplayName(selectedProductChoice)} would you like?`,
              order: null,
            });
          }

          const previousOrder = JSON.parse(JSON.stringify(memory.pendingOrder));
          addOrUpdateOrderItem(memory.pendingOrder, selectedProductChoice, qty);
          const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

          if (!stockCheck.ok) {
            memory.pendingOrder = previousOrder;
            return res.status(stockCheck.status).json({
              reply: stockCheck.reply,
              order: null,
            });
          }

          memory.lastProduct = offeringDisplayName(selectedProductChoice);
          memory.awaitingProductChoice = null;

          return res.json({
            reply: `✅ Got it! I've updated your order:

🛒 New Order Summary:
${formatOrderItems(memory.pendingOrder.items, currency)}

Total: ${formatMoney(memory.pendingOrder.total_price, currency)}

👉 Would you like to proceed with the purchase? (yes/no)`,
            order: null,
          });
        }

        if (isGreetingOnly(message)) {
          return res.json({
            reply: `Hey! I'm still here with you. When you're ready, which ${memory.awaitingProductChoice.keyword} would you like: ${formatProductChoices(pendingChoices, currency)}?`,
            order: null,
          });
        }

        if (isBrowseRequest(message)) {
          return res.json({
            reply: `We have:\n\n${formatProductCatalog(products, currency)}\n\nWhen you're ready, which ${memory.awaitingProductChoice.keyword} would you like: ${formatProductChoices(pendingChoices, currency)}?`,
            order: null,
          });
        }

        return res.json({
          reply: `Sure. Which ${memory.awaitingProductChoice.keyword} would you like: ${formatProductChoices(pendingChoices, currency)}?`,
          order: null,
        });
      }

      if (pendingAmbiguousChoice) {
        memory.awaitingProductChoice = {
          action: "order",
          keyword: pendingAmbiguousChoice.keyword,
          quantity: newQty || null,
          choices: pendingAmbiguousChoice.matches.map(product => offeringDisplayName(product)),
        };

        return res.json({
          reply: `Sure. Which ${pendingAmbiguousChoice.keyword} would you like: ${formatProductChoices(pendingAmbiguousChoice.matches, currency)}?`,
          order: null,
        });
      }

      // ✅ CHANGE PRODUCT (WITH OPTIONAL QTY)
      if (newProduct) {
        const previousOrder = JSON.parse(JSON.stringify(memory.pendingOrder));
        const qty = newQty || 1;
        const unavailableItems = [];

        for (const item of memory.pendingOrder.items) {
          const product = products.find(candidate => candidate._id.toString() === item.product_id.toString()) ||
            findProductByName(item.product, products);
          if (product && item.quantity > product.stock_quantity) {
            unavailableItems.push(item.product);
          }
        }

        for (const productName of unavailableItems) {
          removeOrderItem(memory.pendingOrder, productName);
        }

        const existingItem = memory.pendingOrder.items.find(
          item => item.product_id.toString() === newProduct._id.toString()
        );

        if (existingItem) {
          existingItem.quantity = qty;
          existingItem.total_price = qty * existingItem.unit_price;
        } else {
          memory.pendingOrder.items.push({
            product_id: newProduct._id,
            type: normalizedOfferingType(newProduct.type),
            product: offeringDisplayName(newProduct),
            quantity: qty,
            unit_price: newProduct.price,
            total_price: qty * newProduct.price,
            duration: newProduct.duration || "",
          });
        }

        memory.pendingOrder.total_price = getOrderTotal(memory.pendingOrder.items);
        const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

        if (!stockCheck.ok) {
          if (stockCheck.item?.product_id?.toString() === newProduct._id.toString()) {
            memory.pendingOrder = previousOrder;
          } else {
            clearUnavailablePendingItem(memory, stockCheck);
          }
          return res.status(stockCheck.status).json({
            reply: stockCheck.reply,
            order: null,
          });
        }

        memory.lastProduct = offeringDisplayName(newProduct);

        return res.json({
          reply: `🔄 Got it! I've updated your order:

🛒 New Order Summary:
${formatOrderItems(memory.pendingOrder.items, currency)}

Total: ${formatMoney(memory.pendingOrder.total_price, currency)}

👉 Would you like to proceed with the purchase? (yes/no)`,
          order: null,
        });
      }

      // ✅ UPDATE QUANTITY ONLY
      if (newQty && memory.lastProduct) {
        const existingItem = memory.pendingOrder.items.find(
          item => item.product === memory.lastProduct || item.product === offeringDisplayName(findProductByName(memory.lastProduct, products) || {})
        );

        if (existingItem) {
          const previousOrder = JSON.parse(JSON.stringify(memory.pendingOrder));
          existingItem.quantity = newQty;
          existingItem.total_price = newQty * existingItem.unit_price;
          memory.pendingOrder.total_price = getOrderTotal(memory.pendingOrder.items);
          const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

          if (!stockCheck.ok) {
            memory.pendingOrder = previousOrder;
            return res.status(stockCheck.status).json({
              reply: stockCheck.reply,
              order: null,
            });
          }

          return res.json({
            reply: `✅ Got it! I've updated your order:

🛒 New Order Summary:
${formatOrderItems(memory.pendingOrder.items, currency)}

Total: ${formatMoney(memory.pendingOrder.total_price, currency)}

👉 Would you like to proceed with the purchase? (yes/no)`,
            order: null,
          });
        }
      }

      // ✅ CONFIRM
      if (isYes(message)) {
        if (req.isPublicChat && !hasRequiredCustomerInfo(customer)) {
          return res.json({
            reply: customerDetailsPrompt(customer),
            order: null,
          });
        }

        const stockCheck = await checkStockAvailability(memory.pendingOrder.items, businessId);

        if (!stockCheck.ok) {
          return res.status(stockCheck.status).json({
            reply: stockCheck.reply,
            order: null,
          });
        }

        const order = {
          order_id: await generateOrderId(businessId),
          userId,
          businessId,
          customer,
          ...memory.pendingOrder,
        };

        let stockReduced = false;
        let savedOrder;

        try {
          await reduceStock(order.items, businessId);
          stockReduced = true;
          savedOrder = await Order.create(order);
        } catch (error) {
          if (stockReduced) {
            await restoreStock(order.items, businessId);
          }

          if (error.reply) {
            return res.status(error.status).json({
              reply: error.reply,
              order: null,
            });
          }

          throw error;
        }

        const orderData = savedOrder.toObject();
        memory.pendingOrder = null;
        memory.awaitingProductChoice = null;
        memory.lastCompletedOrder = orderData;
        memory.lastIntent = "order_completed";
        notifyBusinessOfOrder({ business, order: orderData, currency, req });

        return res.json({
          reply: `✅ Your order has been placed.\n\nOrder ID: ${orderData.order_id}\n\n${formatOrderItems(orderData.items, currency)}\n\nTotal: ${formatMoney(orderData.total_price, currency)}`,
          order: orderData,
        });
      }

      // ❌ CANCEL
      if (isNo(message)) {
        memory.pendingOrder = null;

        return res.json({
          reply: "No problem 👍 Your order has been cancelled.",
          order: null,
        });
      }

      // 🤖 UNKNOWN INPUT
      return res.json({
        reply: `You have a pending order:

${formatOrderItems(memory.pendingOrder.items, currency)}

Total: ${formatMoney(memory.pendingOrder.total_price, currency)}

👉 You can:
- Say "yes" to confirm
- Say "no" to cancel
- Add another product (e.g. "add another product")
- Change the last product quantity (e.g. "make it 2")`,
        order: null,
      });
    }

    // =============================
    // 🧠 SYSTEM PROMPT
    // =============================
    const systemPrompt = `
You are an AI assistant for ${business.name}.

ABOUT:
- Business ID: ${business.businessId}
- Business name: ${business.name}
- Tone: ${business.tone}
- Currency: ${business.currency}
- Business description: ${business.description || "not provided"}
- Contact info: ${business.contact_info || "not provided"}
- AI personality: ${business.ai_personality || "helpful and concise"}
- Only use this business's product list when answering product or order questions

PRODUCTS:
${JSON.stringify(productsForPrompt, null, 2)}

RECENT CONTEXT:
- Current business ID: ${businessId}
- Last product the user discussed: ${memory.lastProduct || "none"}

YOUR ROLE:
- Greet users naturally
- Talk like a human
- Talk like you are having a conversation
- Recommend products
- Help users choose
- Guide users to purchase

IMPORTANT ORDER FLOW:
- If user wants to buy → DO NOT confirm order
- instead ask how many they would like to get if they haven't specified it 
- before order is created 
- then → ask: "Would you like to proceed with the purchase?"
- If the user says "that", "it", "those", or "one of those", use the last discussed product from RECENT CONTEXT
- If the user asks for multiple products, return all products in "items"
- If the user mentions an ambiguous product category, ask which exact listed product they want

INTENT:
- "order" → user wants to buy
- "chat" → normal conversation

RETURN JSON ONLY:

{
  "intent": "order" | "chat",
  "product": string | null,
  "quantity": number | null,
  "items": [
    { "product": string, "quantity": number | null }
  ],
  "reply": string
}

RULES:
- Stay inside business
- No external topics
- Match the business tone
- Use ${business.currency} when discussing prices
- Be short
`;

    // =============================
    // 🤖 AI CALL
    // =============================
    let aiResponse;

    try {
      aiResponse = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: message }
        ],
      });
    } catch (err) {
      console.error("OpenAI Error:", err.message);

      return res.json({
        reply: "⚠️ I'm having trouble connecting right now. Please try again.",
        order: null,
      });
    }

    // =============================
    // 🧾 PARSE AI RESPONSE
    // =============================
    let aiData;

    try {
      aiData = JSON.parse(aiResponse.choices[0].message.content);
    } catch {
      return res.json({
        reply: "Sorry, something went wrong.",
        order: null,
      });
    }

    const { intent, product, quantity, items, reply } = aiData;

    const productFromAi = product ? findProductByName(product, products) : null;
    const mentionedProduct = productFromAi || productFromMessage;

    if (mentionedProduct) {
      memory.lastProduct = offeringDisplayName(mentionedProduct);
    }

    if (Array.isArray(items) && items.length > 0) {
      const lastAiItem = items[items.length - 1];
      const lastAiProduct = lastAiItem.product ? findProductByName(lastAiItem.product, products) : null;

      if (lastAiProduct) {
        memory.lastProduct = offeringDisplayName(lastAiProduct);
      }
    }

    // =============================
    // 🛡️ BACKEND SAFETY
    // =============================
    if (intent === "order") {
      let orderItems = normalizeOrderItems(items, product, quantity, message, products);

      if (orderItems.length === 0 && mentionedProduct) {
        orderItems = normalizeOrderItems(
          [{ product: mentionedProduct.name, quantity: quantity || extractQuantity(message) }],
          null,
          null,
          message,
          products
        );
      }

      if (orderItems.length === 0 && memory.lastProduct) {
        orderItems = normalizeOrderItems(
          [{ product: memory.lastProduct, quantity: quantity || extractQuantity(message) }],
          null,
          null,
          message,
          products
        );
      }

      if (ambiguousProductChoice) {
        const ambiguousProductIds = new Set(
          ambiguousProductChoice.matches.map(product => product._id.toString())
        );
        orderItems = orderItems.filter(
          item => !ambiguousProductIds.has(item.product_id.toString())
        );
        const stockCheck = await checkStockAvailability(orderItems, businessId);

        if (!stockCheck.ok) {
          return res.status(stockCheck.status).json({
            reply: stockCheck.reply,
            order: null,
          });
        }

        memory.pendingOrder = {
          items: orderItems,
          total_price: getOrderTotal(orderItems),
        };
        memory.awaitingProductChoice = {
          action: "order",
          keyword: ambiguousProductChoice.keyword,
          quantity: quantity || extractQuantity(message),
          choices: ambiguousProductChoice.matches.map(product => offeringDisplayName(product)),
        };

        const summary = orderItems.length > 0
          ? `\n\nCurrent order:\n${formatOrderItems(orderItems, currency)}\n\nTotal: ${formatMoney(memory.pendingOrder.total_price, currency)}`
          : "";

        return res.json({
          reply: `Sure. Which ${ambiguousProductChoice.keyword} would you like: ${formatProductChoices(ambiguousProductChoice.matches, currency)}?${summary}`,
          order: null,
        });
      }

      if (orderItems.length === 0) {
        return res.json({
          reply: `Sorry, we don’t sell that. We offer: ${validProductNames.join(", ")}.`,
          order: null,
        });
      }

      const missingQuantityItem = orderItems.find(item => !item.quantity);

      if (missingQuantityItem) {
        memory.pendingOrder = {
          items: orderItems,
          total_price: getOrderTotal(orderItems),
        };
        memory.lastProduct = missingQuantityItem.product;

        return res.json({
          reply: `Nice choice! 👌\n\nHow many ${missingQuantityItem.product} would you like?`,
          order: null,
        });
      }

      const stockCheck = await checkStockAvailability(orderItems, businessId);

      if (!stockCheck.ok) {
        return res.status(stockCheck.status).json({
          reply: stockCheck.reply,
          order: null,
        });
      }

      memory.pendingOrder = {
        items: orderItems,
        total_price: getOrderTotal(orderItems),
      };

      return res.json({
        reply: `Great choice!

🛒 Order Summary:
${formatOrderItems(orderItems, currency)}

Total: ${formatMoney(memory.pendingOrder.total_price, currency)}

👉 Would you like to proceed with the purchase? (yes/no)`,
        order: null,
      });
    }

    // =============================
    // 💬 NORMAL CHAT
    // =============================
    return res.json({
      reply,
      order: null,
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      reply: "Server error",
      order: null,
    });
  }
}

app.post("/chat", requireAuth, chatHandler);
app.post("/public/chat/:businessId", loadPublicBusiness, chatHandler);

// 🚀 START SERVER
async function startServer() {
  if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is missing from .env");
  }

  await mongoose.connect(process.env.MONGO_URI, {
    dbName: process.env.MONGO_DB_NAME || "stylehub",
  });

  console.log("MongoDB connected");
  await ensureOfferingIndexes();

  const port = process.env.PORT || 3000;

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

startServer().catch(error => {
  console.error("Startup error:", error.message);
  process.exit(1);
});
