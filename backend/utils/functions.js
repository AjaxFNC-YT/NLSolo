const axios = require("axios");
// /**
//  * Logs a message with optional styling.
//  *
//  * @param {string} string - The message to log.
//  * @param {'info' | 'err' | 'warn' | 'done' | undefined} style - The style of the log.
//  */
// // const log = (string, style) => {
//   const styles = {
//     info: { prefix: chalk.blue("[INFO]"), logFunction: console.log },
//     err: { prefix: chalk.red("[ERROR]"), logFunction: console.error },
//     warn: { prefix: chalk.yellow("[WARNING]"), logFunction: console.warn },
//     done: { prefix: chalk.green("[SUCCESS]"), logFunction: console.log },
//   };

//   const selectedStyle = styles[style] || { logFunction: console.log };
//   selectedStyle.logFunction(`${selectedStyle.prefix || ""} ${string}`);
// };


/**
 * generates a access token using device auths
 *
 * @param {accountid} string - The account id
 * @param {deviceid} string - The device id
 * @param {secret} string - The secret
 * @returns {String} - The access token
 */
const getAccessTokenFromDevice = async (accountId, deviceId, secret) => {
  const response = await axios.post(
    "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
    {
      grant_type: 'device_auth',
      account_id: accountId,
      device_id: deviceId,
      secret: secret,
      token_type: 'eg1'
    },
    {
      headers: {
        'Authorization': 'Basic OThmN2U0MmMyZTNhNGY4NmE3NGViNDNmYmI0MWVkMzk6MGEyNDQ5YTItMDAxYS00NTFlLWFmZWMtM2U4MTI5MDFjNGQ3',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );
  return response.data.access_token;
};

/**
 * does a mcp request
 * @param {operation} string - mcp operation
 * @param {route} string - mcp route
 * @param {profile} string - mcp profile
 * @param {payload} JSON - mcp payload/body
 * @returns {JSON} - MCP response.
 */
const mcpRequest = async (operation, route, profile, payload, accessToken, accountId) => {
  let rq = await axios.post(`https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/profile/${accountId}/${route}/${operation}?profileId=${profile}`, payload, { headers: { "Authorization": `Bearer ${accessToken}` } });
  return rq.data;
}


/**
 * Gets a Exchange code from a access token
 *
 * @param {access_token} string - The Access Token
 * @returns {String} - The Exchange code.
 */
const getExchangeFromAccess = async (access_token) => {
    try {
    headers = {
        'Authorization': `Bearer ${access_token}`
    }
    const rq = await axios.get("https://account-public-service-prod.ol.epicgames.com/account/api/oauth/exchange", { headers })
    return { status: 200, code: rq.data.code }
} catch (e) {
    return { status: 401, error: e.message };
}
}


module.exports = {
  getAccessTokenFromDevice,
  mcpRequest,
  getExchangeFromAccess
};