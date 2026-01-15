const express = require("express");
const router = express.Router();
const User = require("../Schema/Model");
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require("../utils/config jwt");
const logger = require("../utils/logger");


// COOKIE OPTIONS
const cookieOptions = {
  httpOnly: true,
  secure: true, // Required for SameSite=None
  sameSite: "None", // Required for cross-site (Vercel -> Hostinger)
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 Days
};

// REFRESH TOKEN ENDPOINT
router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ success: false, message: "No refresh token provided" });
  }

  // Clear cookie immediately if something fails, for safety
  const clearCookie = () => res.clearCookie("refreshToken", { ...cookieOptions, maxAge: 0 });

  try {
    // 1. Verify Signature
    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      clearCookie();
      return res.status(403).json({ success: false, message: "Invalid refresh token" });
    }

    // 2. Check Whitelist
    const user = await User.findById(decoded.id);
    if (!user) {
      clearCookie();
      return res.status(403).json({ success: false, message: "User not found" });
    }

    if (!user.refreshTokens.includes(refreshToken)) {
      logger.warn(`[SECURITY] Token Reuse Detected for User: ${user.email}`);

      user.refreshTokens = [];
      await user.save();
      clearCookie();
      return res.status(403).json({ success: false, message: "Security alert: Session invalidated." });
    }

    // 3. Token Rotation (Aggregation pipeline to avoid Mongo path conflict)
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    const updatedUser = await User.findOneAndUpdate(
      { _id: user._id, refreshTokens: refreshToken },
      [
        {
          $set: {
            refreshTokens: {
              $concatArrays: [
                {
                  $filter: {
                    input: "$refreshTokens",
                    as: "t",
                    cond: { $ne: ["$$t", refreshToken] },
                  },
                },
                [newRefreshToken],
              ],
            },
          },
        },
        {
          $set: {
            refreshTokens: { $slice: ["$refreshTokens", -10] },
          },
        },
      ],
      { new: true }
    );

    if (!updatedUser) {
      clearCookie();
      return res.status(403).json({
        success: false,
        message: "Token already rotated or session invalidated",
      });
    }

    // 4. Send Response
    res.cookie("refreshToken", newRefreshToken, cookieOptions);
    res.status(200).json({
      success: true,
      accessToken: newAccessToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      }
    });

  } catch (error) {
    logger.error("CRITICAL Refresh Error:", error);

    clearCookie();
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// LOGOUT ENDPOINT
router.post("/logout", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    try {
      const user = await User.findOne({ refreshTokens: refreshToken });
      if (user) {
        // Remove this specific token from DB
        user.refreshTokens = user.refreshTokens.filter((t) => t !== refreshToken);
        await user.save();
      }
    } catch (err) {
      logger.error("Logout DB Error:", err);

      // Continue to clear cookie anyway
    }
  }

  res.clearCookie("refreshToken", { ...cookieOptions, maxAge: 0 });
  res.status(200).json({ success: true, message: "Logged out successfully" });
});

module.exports = router;
