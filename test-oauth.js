/**
 * OAuth2 Test Script
 *
 * Run this to verify your OAuth2 setup is working correctly
 * 
 */

const { initializeOAuth, authenticatedFetch, getValidAccessToken } = require("./utils/oauth");
require("dotenv").config();

(async () => {
        console.log("=".repeat(60));
        console.log("iRacing OAuth2 Test Script");
        console.log("=".repeat(60));

        try {
                // Step 1: Check environment variables
                console.log("\n1. Checking environment variables...");
                const requiredVars = ["IR_USERNAME", "IR_PASSWORD", "IR_OAUTH_CLIENT_ID", "IR_OAUTH_SECRET"];
                const missing = requiredVars.filter((v) => !process.env[v]);

                if (missing.length > 0) {
                        console.error(" Missing required environment variables:", missing.join(", "));
                        console.log("\nYour .env file should contain:");
                        console.log("IR_USERNAME= ir username here");
                        console.log("IR_PASSWORD=your_password");
                        console.log("IR_OAUTH_CLIENT_ID=oauth client here");
                        console.log("IR_OAUTH_SECRET=your_oauth_secret");
                        process.exit(1);
                }
                console.log("✓ All required environment variables present");

                // Step 2: Initialize OAuth
                console.log("\n2. Initializing OAuth2...");
                await initializeOAuth();
                console.log("✓ OAuth2 initialized successfully");

                // Step 3: Get access token
                console.log("\n3. Getting access token...");
                const token = await getValidAccessToken();
                console.log("✓ Access token obtained");
                console.log(`   Token (first 20 chars): ${token.substring(0, 20)}...`);

                // Step 4: Test API call - get member info
                console.log("\n4. Testing API call (member info)...");
                const custId = 123456; // You can change this to your own cust_id
                const response = await authenticatedFetch(
                        `https://members-ng.iracing.com/data/stats/member_career?cust_id=${custId}`
                );

                if (!response.ok) {
                        console.error(`
                        API call failed: ${response.status} ${response.statusText}`);
                        const text = await response.text();
                        console.error("   Response:", text);
                        process.exit(1);
                }

                const data = await response.json();
                console.log("✓ API call successful");
                console.log(`   Retrieved data for customer ID: ${custId}`);

                // Step 5: Test another endpoint - get current season
                console.log("\n5. Testing another API endpoint (current season)...");
                const seasonResponse = await authenticatedFetch("https://members-ng.iracing.com/data/series/seasons");

                if (!seasonResponse.ok) {
                        console.error(`Season API call failed: ${seasonResponse.status}`);
                        process.exit(1);
                }

                const seasonData = await seasonResponse.json();
                console.log("✓ Season API call successful");
                console.log(`   Retrieved ${seasonData.length || 0} seasons`);

                // Success!
                console.log("\n" + "=".repeat(60));
                console.log("✓ All tests passed! OAuth2 is working correctly.");
                console.log("=".repeat(60));
                console.log("\nYou can now:");
                
                console.log("2. Run your tools with OAuth2 authentication");
        
                console.log("\n");
                process.exit(0);
        } catch (error) {
                console.error("\n Error during OAuth test:");
                console.error(error);
                console.log("\nTroubleshooting:");
                console.log("1. Check your .env file has correct credentials");
                console.log("2. Verify your OAuth secret is correct");
                console.log("3. Ensure your username is authorized for this client");
                console.log("4. Check if you're being rate limited");
                process.exit(1);
        }
})();
