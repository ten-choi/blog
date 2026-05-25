import fs from "fs";
import path from "path";
import http from "http";
import { URL } from "url";
import dotenv from "dotenv";
import { google } from "googleapis";
import type { OAuth2Client, Credentials } from "google-auth-library";

dotenv.config();

const SCOPES = ["https://www.googleapis.com/auth/blogger"];
const ENV_PATH = path.join(__dirname, "..", "..", ".env");
const ENV_KEY = "BLOGGER_REFRESH_TOKEN";

function loadClientCreds(): { client_id: string; client_secret: string } {
  const client_id = process.env.BLOGGER_CLIENT_ID;
  const client_secret = process.env.BLOGGER_TOKEN_PROD;
  if (!client_id) {
    throw new Error(
      "BLOGGER_CLIENT_ID is not set in .env. Put the OAuth client_id (e.g. 5662...apps.googleusercontent.com) from Google Cloud Console there."
    );
  }
  if (!client_secret) {
    throw new Error(
      "BLOGGER_TOKEN_PROD is not set in .env. Put the OAuth client_secret (GOCSPX-...) from Google Cloud Console there."
    );
  }
  return { client_id, client_secret };
}

function loadRefreshTokenFromEnv(): string | null {
  const t = process.env[ENV_KEY];
  return t && t.length > 0 ? t : null;
}

function saveRefreshTokenToEnv(refresh_token: string): void {
  let envContent = "";
  if (fs.existsSync(ENV_PATH)) {
    envContent = fs.readFileSync(ENV_PATH, "utf8");
  }
  const line = `${ENV_KEY}=${refresh_token}`;
  const pattern = new RegExp(`^${ENV_KEY}=.*$`, "m");
  if (pattern.test(envContent)) {
    envContent = envContent.replace(pattern, line);
  } else {
    const prefix = envContent.length > 0 && !envContent.endsWith("\n") ? "\n" : "";
    envContent += prefix + line + "\n";
  }
  fs.writeFileSync(ENV_PATH, envContent, "utf8");
  process.env[ENV_KEY] = refresh_token;
  console.log(`${ENV_KEY} saved to ${ENV_PATH}`);
}

function runLoopbackAuth(
  client_id: string,
  client_secret: string
): Promise<{ tokens: Credentials; client: OAuth2Client }> {
  return new Promise((resolve, reject) => {
    let client: OAuth2Client | null = null;

    const server = http.createServer(async (req, res) => {
      try {
        if (!req.url || !client) return;
        const reqUrl = new URL(req.url, `http://localhost`);
        const code = reqUrl.searchParams.get("code");
        const err = reqUrl.searchParams.get("error");

        if (err) {
          res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
          res.end(`Authorization error: ${err}`);
          server.close();
          reject(new Error(`OAuth error: ${err}`));
          return;
        }

        if (!code) {
          res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
          res.end("Missing 'code' query parameter.");
          return;
        }

        const { tokens } = await client.getToken(code);
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(
          "<html><body><h2>Authorization successful.</h2><p>You can close this tab and return to the terminal.</p></body></html>"
        );
        server.close();
        resolve({ tokens, client });
      } catch (e) {
        try {
          res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
          res.end(`Error: ${(e as Error).message}`);
        } catch {
          // ignore
        }
        server.close();
        reject(e);
      }
    });

    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Failed to bind local auth server."));
        return;
      }
      const port = address.port;
      const redirectUri = `http://localhost:${port}`;
      client = new google.auth.OAuth2(client_id, client_secret, redirectUri);

      const authUrl = client.generateAuthUrl({
        access_type: "offline",
        prompt: "consent",
        scope: SCOPES,
      });

      console.log("\nOpen the following URL in your browser to authorize:\n");
      console.log(authUrl);
      console.log(`\nWaiting for redirect on ${redirectUri} ...`);
    });

    server.on("error", reject);
  });
}

export async function getAuthClient(): Promise<OAuth2Client> {
  const { client_id, client_secret } = loadClientCreds();

  const refreshToken = loadRefreshTokenFromEnv();
  if (refreshToken) {
    const oAuth2Client = new google.auth.OAuth2(client_id, client_secret);
    oAuth2Client.setCredentials({ refresh_token: refreshToken });
    oAuth2Client.on("tokens", (tokens) => {
      if (tokens.refresh_token && tokens.refresh_token !== refreshToken) {
        saveRefreshTokenToEnv(tokens.refresh_token);
      }
    });
    return oAuth2Client;
  }

  const { tokens, client } = await runLoopbackAuth(client_id, client_secret);
  if (!tokens.refresh_token) {
    throw new Error(
      "Authorization did not return a refresh_token. Revoke access at https://myaccount.google.com/permissions and re-authorize."
    );
  }
  saveRefreshTokenToEnv(tokens.refresh_token);
  client.setCredentials(tokens);
  return client;
}

if (require.main === module) {
  getAuthClient()
    .then(() => {
      console.log("Authorization complete.");
    })
    .catch((e) => {
      console.error("Authorization failed:", (e as Error).message);
      process.exit(1);
    });
}
