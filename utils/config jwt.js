const jwt = require("jsonwebtoken");
const secretKey = require("./config cypt");

// Ensure Refresh Token Secret exists or use fallback (In production, this MUST be in ENV)
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || "fallback_refresh_secret_key_secure_random";

function generateAccessToken(user) {
  const payload = {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role,
  };
  // Short-lived Access Token (e.g., 15 minutes)
  return jwt.sign(payload, secretKey, { expiresIn: "15m" });
}

function generateRefreshToken(user) {
  const payload = {
    id: user._id,
    // Add randomness to ensure unique tokens even if generated at same second
    random: Math.random().toString(36).substring(7)
  };
  // Long-lived Refresh Token (e.g., 7 days)
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: "7d" });
}

// Verification for Access Token (Middleware)
const verifyToken = (tokenOrReq, resOrNext, next) => {
  let token;
  let res;
  let callback;

  if (typeof tokenOrReq === "string") {
    token = tokenOrReq;
    callback = resOrNext;
  } else {
    token = tokenOrReq.header("Authorization")?.split(" ")[1];
    res = resOrNext;
    callback = next;
  }

  if (!token) {
    if (res) {
      return res.status(403).json({ success: false, message: "No token provided, access denied." });
    } else {
      throw new Error("No token provided");
    }
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    if (res) {
      tokenOrReq.user = decoded;
    }
    if (callback) callback(null, decoded);
    return decoded;
  } catch (error) {
    if (res) {
      // 401 triggers frontend interceptor to refresh
      return res.status(401).json({ success: false, message: "Invalid or expired token." });
    } else {
      throw new Error("Invalid token");
    }
  }
};

// Verification for Refresh Token (Manual)
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, REFRESH_SECRET);
  } catch (error) {
    return null; // Expired or Invalid
  }
};

module.exports = { generateAccessToken, generateRefreshToken, verifyToken, verifyRefreshToken };
