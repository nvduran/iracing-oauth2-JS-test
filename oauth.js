/**
 * iRacing OAuth2 Authentication Module
 *
 * Handles OAuth2 Password Limited Grant flow for iRacing API access
 * See: https://oauth.iracing.com/docs for full documentation
 */

const fetch = require("node-fetch");
const crypto = require("crypto");
require("dotenv").config();

// Token storage
let accessToken = null;
let refreshToken = null;
let tokenExpiresAt = null;
let refreshTokenExpiresAt = null;

/**
 * Masks a secret using SHA256 hashing as required by iRacing OAuth2 API
 * @param {string} secret - The secret to mask (password or client_secret)
 * @param {string} id - The identifier to use in masking (username or client_id)
 * @returns {string} Base64-encoded SHA256 hash
 */
function maskSecret(secret, id) {
        const normalizedId = id.trim().toLowerCase();
        const combined = `${secret}${normalizedId}`;
        const hash = crypto.createHash("sha256").update(combined).digest("base64");
        return hash;
}

/**
 * Obtains initial access and refresh tokens using Password Limited Grant
 * @returns {Promise<boolean>} True if authentication successful
 */
async function getInitialToken() {
        try {
                const clientId = process.env.IR_OAUTH_CLIENT_ID || "iracingdatacom";
                const clientSecret = process.env.IR_OAUTH_SECRET;
                const username = process.env.IR_USERNAME;
                const password = process.env.IR_PASSWORD;

                if (!clientSecret || !username || !password) {
                        throw new Error("Missing required OAuth credentials in .env file");
                }

                // Mask the client secret and password as required
                const maskedClientSecret = maskSecret(clientSecret, clientId);
                const maskedPassword = maskSecret(password, username);

                // Build form data
                const params = new URLSearchParams();
                params.append("grant_type", "password_limited");
                params.append("client_id", clientId);
                params.append("client_secret", maskedClientSecret);
                params.append("username", username);
                params.append("password", maskedPassword);
                params.append("scope", "iracing.auth");

                console.log("Requesting initial OAuth token...");

                const response = await fetch("https://oauth.iracing.com/oauth2/token", {
                        method: "POST",
                        headers: {
                                "Content-Type": "application/x-www-form-urlencoded",
                        },
                        body: params.toString(),
                });

                // Check for rate limiting (both 400 and 401 can indicate rate limits)
                if (response.status === 400 || response.status === 401) {
                        const errorText = await response.text();
                        const retryAfter = response.headers.get("Retry-After");

                        // Parse the error to check if it's a rate limit
                        if (errorText.includes("rate limit exceeded") || retryAfter) {
                                const waitTime = retryAfter || "unknown";
                                console.error(`⚠️  RATE LIMITED! Must wait ${waitTime} seconds before retry`);
                                console.error(`This is likely due to multiple server restarts/deployments`);
                                throw new Error(`RATE_LIMIT_EXCEEDED: Retry after ${waitTime} seconds - ${errorText}`);
                        }

                        throw new Error(`OAuth token request failed: ${response.status} - ${errorText}`);
                }

                if (!response.ok) {
                        const errorText = await response.text();
                        throw new Error(`OAuth token request failed: ${response.status} - ${errorText}`);
                }

                const data = await response.json();

                // Store tokens and expiration times
                accessToken = data.access_token;
                refreshToken = data.refresh_token;
                tokenExpiresAt = Date.now() + data.expires_in * 1000;
                refreshTokenExpiresAt = data.refresh_token_expires_in ? Date.now() + data.refresh_token_expires_in * 1000 : null;

                console.log(`OAuth token obtained. Expires in ${data.expires_in} seconds`);
                console.log(`Refresh token expires in ${data.refresh_token_expires_in} seconds`);

                // Log rate limit info if available
                const rateLimitLimit = response.headers.get("RateLimit-Limit");
                const rateLimitRemaining = response.headers.get("RateLimit-Remaining");
                const rateLimitReset = response.headers.get("RateLimit-Reset");

                if (rateLimitLimit) {
                        console.log(`Rate Limit: ${rateLimitRemaining}/${rateLimitLimit} (resets in ${rateLimitReset}s)`);
                }

                return true;
        } catch (error) {
                console.error("Error getting initial OAuth token:", error.message);
                throw error;
        }
}

/**
 * Refreshes the access token using the refresh token
 * @returns {Promise<boolean>} True if refresh successful
 */
async function refreshAccessToken() {
        try {
                if (!refreshToken) {
                        console.log("No refresh token available, getting initial token");
                        return await getInitialToken();
                }

                const clientId = process.env.IR_OAUTH_CLIENT_ID || "iracingdatacom";
                const clientSecret = process.env.IR_OAUTH_SECRET;

                const maskedClientSecret = maskSecret(clientSecret, clientId);

                const params = new URLSearchParams();
                params.append("grant_type", "refresh_token");
                params.append("client_id", clientId);
                params.append("client_secret", maskedClientSecret);
                params.append("refresh_token", refreshToken);

                console.log("Refreshing OAuth token...");

                const response = await fetch("https://oauth.iracing.com/oauth2/token", {
                        method: "POST",
                        headers: {
                                "Content-Type": "application/x-www-form-urlencoded",
                        },
                        body: params.toString(),
                });

                if (!response.ok) {
                        const errorText = await response.text();
                        console.error(`Token refresh failed: ${response.status} - ${errorText}`);
                        // If refresh fails, try getting a new token
                        console.log("Refresh failed, getting new initial token");
                        return await getInitialToken();
                }

                const data = await response.json();

                // Update tokens and expiration times
                accessToken = data.access_token;
                refreshToken = data.refresh_token; // New refresh token is issued
                tokenExpiresAt = Date.now() + data.expires_in * 1000;
                refreshTokenExpiresAt = data.refresh_token_expires_in ? Date.now() + data.refresh_token_expires_in * 1000 : null;

                console.log(`OAuth token refreshed. Expires in ${data.expires_in} seconds`);

                return true;
        } catch (error) {
                console.error("Error refreshing OAuth token:", error.message);
                // Fall back to getting initial token
                return await getInitialToken();
        }
}

/**
 * Gets a valid access token, refreshing if necessary
 * @returns {Promise<string>} Valid access token
 */
async function getValidAccessToken() {
        // Check if we have a token and it's still valid (with 30 second buffer)
        if (accessToken && tokenExpiresAt && Date.now() < tokenExpiresAt - 30000) {
                return accessToken;
        }

        // Check if refresh token is still valid
        if (refreshToken && refreshTokenExpiresAt && Date.now() < refreshTokenExpiresAt - 30000) {
                await refreshAccessToken();
        } else {
                await getInitialToken();
        }

        return accessToken;
}

/**
 * Makes an authenticated request to the iRacing API
 * @param {string} url - The API endpoint URL
 * @param {object} options - Fetch options (method, headers, body, etc.)
 * @returns {Promise<Response>} Fetch response
 */
async function authenticatedFetch(url, options = {}) {
        const token = await getValidAccessToken();

        const headers = {
                ...options.headers,
                Authorization: `Bearer ${token}`,
        };

        return fetch(url, {
                ...options,
                headers,
        });
}

/**
 * Initializes OAuth by getting the initial token
 * Call this on application startup
 */
async function initializeOAuth() {
        try {
                await getInitialToken();
                console.log("OAuth initialization successful");
        } catch (error) {
                console.error("OAuth initialization failed:", error.message);
                throw error;
        }
}

module.exports = {
        initializeOAuth,
        getValidAccessToken,
        authenticatedFetch,
        maskSecret, // Export for testing purposes
};
