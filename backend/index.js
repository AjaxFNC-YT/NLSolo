const { Client } = require('fnbr');
const { readFile, writeFile } = require('fs').promises;
const { get } = require('request-promise');
const fs = require('fs')
const path = require('path');
const axios = require("axios");
const WebSocketClient = require('websocket').client;
const crypto = require('crypto');
const GetVersion = require('./utils/version');
const { mcpRequest } = require("./utils/functions")
const readline = require('readline');
const os = require('os');
const chalk = require('ansi-colors');

(async () => {
    const configFilePath = path.join(__dirname, 'config', 'config.json');
    function loadConfig() {
        try {
            const configData = fs.readFileSync(configFilePath, 'utf8');
            const config = JSON.parse(configData);
            return config;
        } catch (err) {
            console.error('Error loading config:', err);
            return null;
        }
    }
    let config = loadConfig();
    let auth;


    const args = process.argv.slice(2); // Skip the first two elements
    
    // Log the arguments
    console.log('Arguments:', args['0']);
    

    let mmMapcode, mmRegion, mmPrivacy;
    mmMapcode = args['0'];
    mmRegion = args['1'];
    mmPrivacy = args['2'];
    botAuthorizationcode = args['3'];
    // Access command-line arguments


    if (!botAuthorizationcode) {
        try {
            auth = { deviceAuth: JSON.parse(await readFile('./deviceAuth.json')) };
          } catch (e) {
            console.log(e)
            //auth = { authorizationCode: async () => Client.consoleQuestion(chalk.cyanBright('Get authorization code from: https://rebrand.ly/authcode\nIf Code is null, login to epicgames and retry.\n\nPlease enter an authorization code: ')) };
          }
    } else {
        auth = { authorizationCode: botAuthorizationcode }
    }

    const client = new Client({ auth });

    client.on('deviceauth:created', (da) => writeFile('./deviceAuth.json', JSON.stringify(da, null, 2)));

    async function getNetCL() {
        let error = false;
        try {
        bearer = client.auth.sessions.get("fortnite").accessToken;
        } catch (e) {
            if (e instanceof TypeError) {
                error=true
                console.log(chalk.redBright("\nInvalid authorization code, please get authorzation code from https://rebrand.ly/authcode/"))
                    if (error = true) {
                    process.exit(1)
                    }
                  }
            }
        const url = "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/matchmaking/session/matchMakingRequest";
        const payload = {
            criteria: [],
            openPlayersRequired: 1,
            buildUniqueId: "",
            maxResults: 1
        };
        const headers = {
            'Authorization': `Bearer ${bearer}`,
            'Content-Type': 'application/json'
        };
    
        try {
            const response = await axios.post(url, payload, { headers });
            return response.data[0].attributes.buildUniqueId_s;
        } catch (error) {
            if (error.response) {
                console.clear()
                console.error('\nServer Error:', error.response.data.errorMessage);
                if (error.response.data.errorCode === "errors.com.epicgames.common.missing_action") {
                    if (fs.existsSync('deviceauth.json')) {
                        fs.unlinkSync('deviceauth.json');
                        console.log('Account is matchmaking banned, please use a different account.');
                    }
                    process.exit(1); // Stop this shit
                }
            } else if (error.request) {
                console.error('Network Error:', error.message);
            } else {
                console.error('Error:', error.message);
            }
        }
    }

  async function getmap(mapcode, alldata) {
    let bearrertkn = client.auth.sessions.get("fortnite").accessToken;
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${bearrertkn}`
    };

    try {
        const response = await axios.get(`https://links-public-service-live.ol.epicgames.com/links/api/fn/mnemonic/${mapcode}`, {
            headers: headers
        });

        if (alldata == true) {
            return JSON.stringify(response.data, null, 2);
        } else {
            let projectId = response.data.metadata.projectId;
            if (!projectId) {
                projectId = 404;
            }
            return projectId;
        }
    } catch (error) {
        return error;
    }
}

const fixPath = (path) => path
  .replace(/^FortniteGame\/Content/, '/Game')
  .replace(/FortniteGame\/Plugins\/GameFeatures\/BRCosmetics\/Content/, '/BRCosmetics')
  .split('/')
  .slice(0, -1)
  .join('/');




    function registerMM() {
        accessToken = client.auth.sessions.get("fortnite").accessToken;
        mcpRequest("QueryProfile", "client", "athena", {}, accessToken, client.user.self.id)
        mcpRequest("QueryProfile", "client", "common_core", {}, accessToken, client.user.self.id)
        console.log(chalk.greenBright("\nMatchmaking Initialized."))
    }






    function calcChecksum(payload, signature) {
        const token = "Don'tMessWithMMS";
        const plaintext =
            payload.slice(10, 20) + token + signature.slice(2, 10);

        const data = Buffer.from(plaintext, 'utf16le');

        const hashObject = crypto.createHash('sha1');

        const hashDigest = hashObject.update(data).digest();

        return Buffer.from(hashDigest.subarray(2, 10)).toString('hex').toUpperCase();
    }
    let currentuseragent = null;
    let currentnetcl = null;



    process.stdout.write('\x1b[33mBot starting...\x1b[0m');
    try {
    await client.login();
    } catch (e) {}
    const lastest = await GetVersion();
    const Platform = os.platform() === "win32" ? "Windows" : os.platform();
    const UserAgent = `Fortnite/${lastest.replace('-Windows', '')} ${Platform}/${os.release()}`

    currentuseragent = UserAgent
    
    currentnetcl = await getNetCL();
    registerMM();

    process.stdout.clearLine();
    process.stdout.cursorTo(0);

    console.log(`\n\x1b[32mBot started as ${client.user.self.displayName}!\x1b[0m`);

    await client.party.me.setOutfit("CID_NPC_Athena_Commando_M_HightowerHenchman", [], [], fixPath("FortniteGame/Plugins/GameFeatures/BRCosmetics/Content/Athena/Items/Cosmetics/Characters/CID_NPC_Athena_Commando_M_HightowerHenchman"));
    await client.party.me.setLevel(0);
    console.log(chalk.yellowBright("Set Party Outfit, Pickaxe, Level, and Banner."))
    client.setStatus("NLsolo | discord.gg/namelessct")
    
    async function mainMMBot() {
    
    let map, region, privatemms;
    var WSClient = new WebSocketClient();
    let latest_payload = {};
      map = mmMapcode
      region = mmRegion
      privatemms = mmPrivacy

  let mapdata;

  try {
      map = map.replace("<", "").replace(">", "");
      region = region.replace("<", "").replace(">", "");
      privatemms = privatemms.replace("<", "").replace(">", "");
  } catch (e) {}

  try {
      if (!map.includes("-")) {
          map = map.slice(0, 4) + '-' + map.slice(4, 8) + '-' + map.slice(8);
      }
  } catch (e) {
      map = map;
  }

  let netcl = currentnetcl;
  let useragent = currentuseragent;
  console.log(chalk.yellowBright(`[MATCHMAKING] UserAgent: ${useragent} --> NetCL: ${netcl}`));
  

  region = region.toLowerCase();
  const validRegions = {
      "nae": "NAE",
      "naw": "NAW",
      "eu": "EU",
      "oce": "OCE",
      "br": "BR",
      "me": "ME",
      "asia": "ASIA",
      "nac": "NAC"
  };

  if (!validRegions[region]) {
      console.clear()
      console.log(chalk.yellowBright(`${region} is not a valid region. Please select a region from the list below:
      nae - North America East
      naw - North America West
      eu - Europe
      Asia - Asia
      oce - Oceania
      br - Brazil
      me - Middle East
      nac - North America Central.`));
      return mainMMBot();
  }

  region = validRegions[region];
  console.log(chalk.greenBright("Generating matchmaking ticket..."));
  let mapinf = await getmap(map, true);

  if (mapinf.includes("NONE-AUTH")) {
      return "NONE-AUTH";
  } else {
      try {
          const mapino = await getmap(map, true);
          const mapinfo = JSON.parse(mapino);
          mapdata = mapinfo;
          console.log(chalk.blueBright(`Match Info:
          - Mapcode: ${map}
          - Name: ${mapinfo.metadata.title}
          - Region: ${region}
          - Private Game: ${privatemms}
          - Creator: ${mapinfo.creatorName}`));
      } catch (e) {
          console.log(e);
        console.log(`Error: ${e}`);
      }
  }

  var query = new URLSearchParams();
  let partyPlayerIds = client.party?.members?.map(m => m.id);
  const bucketId = `${netcl}:1:${region}:noplaylist`;
  let prodid = await getmap(map.split('?')[0], false);

  if (prodid === "NONE") {
      return console.log(chalk.redBright("The map wasn't found. Or you provided a Creative 1.0 Map. Find creative 2.0 Maps from: https://fortnite.gg/creative?uefn"));
  }

  if (prodid === 'NONE-AUTH') {
      return console.log("Failed to fetch auth.");
  }

  let pplids = '';
  try {
      pplids = partyPlayerIds.join(",");
  } catch (e) {
      return console.log(`Error, ${e}`);
  }

  query.append("partyPlayerIds", pplids);
  query.append("player.platform", "Windows");
  query.append("player.option.partyId", client.party.id);
  query.append("input.KBM", "true");
  query.append("player.input", "KBM");
  query.append("bucketId", bucketId);
  query.append("player.option.linkCode", map);
  query.append("player.option.groupBy", map);

  if (prodid !== "NONE" && prodid !== "[object Promise]") {
      query.append("player.option.projectID", prodid);
  }

  query.append("player.option.privateMMS", privatemms);
  const url = `https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/matchmakingservice/ticket/player/${client.user.self.id}?${query}`;
  let bearrertkn = "";

  try {
    bearrertkn = client.auth.sessions.get("fortnite").accessToken;
  } catch (e) {
    console.log(e);
  }

  axios.get(url, {
    headers: { "User-Agent": useragent, "Authorization": "Bearer " + bearrertkn }
})
.then(function(response) {
    console.log(chalk.greenBright("Successfully generated a matchmaking ticket!"));
    const ticket_payload = response.data.payload;
    const ticket_signature = response.data.signature;
    const ticket_type = response.data.ticketType;
    const websocket_url = response.data.serviceUrl;
    console.log(chalk.yellowBright("Generating checksum..."));
    const checksum = calcChecksum(ticket_payload, ticket_signature);
    console.log(chalk.greenBright("Successfully generated checksum!: " + checksum));
    console.log(chalk.yellowBright("Connecting to matchmaking WebSocket..."));
    var extraHeaders = {
        'Authorization': `Epic-Signed ${ticket_type} ${ticket_payload} ${ticket_signature} ${checksum}`
    };
    WSClient.connect(websocket_url, null, null, extraHeaders);
})
.catch(function(error) {
    if (error.response.data.errorMessage.includes('valid profile')) {
        return console.log(chalk.redBright('This Account Is Not Initialized. Please Initialize First!'));
    } else {
        return console.log(chalk.redBright("Encountered An Error With Matchmaking Ticket: " + error.response.data.errorMessage));
    }
});

WSClient.on('connectFailed', function(error) {
    console.log('Connect Error: ' + error.toString());
});

WSClient.on('connect', function(connection) {
    console.log(chalk.greenBright('Connected to Matchmaking!'));
    connection.on('error', function(error) {
        console.log("Connection Error: " + error.toString());
        return;
    });

    connection.on('close', function() {
        if (latest_payload.payload.sessionId) {
            const session_id = latest_payload.payload.sessionId;
            console.log(chalk.yellowBright("Session ID: " + session_id));
            const url = `https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/matchmaking/session/${session_id}`;
            axios.get(url, {
                headers: { "User-Agent": useragent, "Authorization": "Bearer " + bearrertkn }
            })
            .then(function(response) {
                const session_data = response.data;
                console.log(chalk.yellowBright("Updating XMPP Presence..."));
                client.xmpp.sendStatus({
                    "Status": `NLSolo | ${mapdata.metadata.title}`,
                    "bIsPlaying": true,
                    "bIsJoinable": true,
                    "bHasVoiceSupport": false,
                    "SessionId": session_id,
                    "ProductName": "Fortnite",
                    "Properties": {
                        "FortBasicInfo_j": {
                            "homeBaseRating": 0
                        },
                        "FortLFG_I": "0",
                        "FortPartySize_i": 1,
                        "FortSubGame_i": 1,
                        "_s": map,
                        "FortGameplayStats_j": {
                            "state": "",
                            "playlist": "None",
                            "numKills": 0,
                            "bFellToDeath": false
                        },
                        "SocialStatus_j": {
                            "attendingSocialEventIds": []
                        },
                        "InUnjoinableMatch_b": false,
                        "party.joininfodata.286331153_j": {
                            "sourceId": client.user.self.id,
                            "sourceDisplayName": client.user.self.displayName,
                            "sourcePlatform": "WIN",
                            "partyId": client.party.id,
                            "partyTypeId": 286331153,
                            "key": "k",
                            "appId": "Fortnite",
                            "buildId": "1:3:",
                            "partyFlags": 6,
                            "notAcceptingReason": 0,
                            "pc": 1
                        },
                        "ServerPlayerCount_i": 1,
                        "GamePlaylistName_s": "Playlist_VK_Play",
                        "Event_PartyMaxSize_s": "16",
                        "Event_PartySize_s": "1",
                        "Event_PlayersAlive_s": "1",
                        "GameSessionJoinKey_s": session_data["attributes"]['SESSIONKEY_s']
                    }
                });
                console.log(chalk.greenBright("Status updated! You can join now."));
                const rl = readline.createInterface({
                    input: process.stdin,
                    output: process.stdout
                  });
                  function promptUser() {
                    rl.question(chalk.cyanBright('Press Enter to create new match...\n'), (input) => {
                        client.setStatus("NLsolo | discord.gg/namelessct")
                        rl.close();
                        process.exit(1)

                    });
                  }
                    promptUser()

            })
            .catch(function(error) {
                console.log(error);
            });
        }
    });

    connection.on('message', function(message) {
        if (message.type === 'utf8') {
            // console.log("Received: '" + message.utf8Data + "'");
            try {
                latest_payload = JSON.parse(message.utf8Data);
            } catch (e) { }

            if (latest_payload.payload.queuedPlayers) {
                connection.send(JSON.stringify({ "name": "Exec", "payload": { "command": "p.StartMatch" } }));
            }
        }
    });
});
    }
  mainMMBot()    
    client.on('party:invite', (inv) => {
      try {
        if (config.inviteaccept === true) {
            inv.accept()
        } else {
          return;
        }
        console.log(chalk.yellowBright(`party inv from: ${inv.sender.displayName}`));
      } catch (e) {
        console.log(e)
      }
    });

client.on('party:member:joined', (member) => {
  if (client.party.size === "1" || client.party.size===1) return;
  client.party.chat.send("Welcome to my party\nReminder: Joining my party can cause nokick to fail.")
});


client.on('friend:request', (req) => {
    try {
        if (config.friendaccept === true) {
            req.accept()
        } else {
            req.decline()
            }
        console.log(chalk.yellowBright(`party inv from: ${inv.sender.displayName}`));
      } catch (e) {
        console.log(e)
      }
})

})();