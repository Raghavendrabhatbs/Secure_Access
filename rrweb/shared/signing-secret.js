const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

function getSigningSecret() {
  const configuredSecret = process.env.RRWEB_SIGNING_SECRET;
  if (configuredSecret) {
    if (Buffer.byteLength(configuredSecret) < 32) {
      throw new Error(
        "RRWEB_SIGNING_SECRET must contain at least 32 bytes"
      );
    }

    return configuredSecret;
  }

  const secretPath =
    process.env.RRWEB_SIGNING_SECRET_FILE ||
    path.join(
      process.env.XDG_CONFIG_HOME ||
        path.join(os.homedir(), ".config"),
      "secureaccess",
      "rrweb-signing-secret"
    );

  fs.mkdirSync(path.dirname(secretPath), {
    recursive: true,
    mode: 0o700,
  });

  let secret;

  try {
    const descriptor = fs.openSync(secretPath, "wx", 0o600);
    try {
      secret = crypto.randomBytes(32).toString("base64url");
      fs.writeFileSync(descriptor, `${secret}\n`, "utf8");
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (error) {
    if (error.code !== "EEXIST") {
      throw new Error(
        `Unable to create rrweb signing secret at ${secretPath}: ${error.message}`,
        { cause: error }
      );
    }
  }

  if (!secret) {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        secret = fs.readFileSync(secretPath, "utf8").trim();
      } catch (error) {
        throw new Error(
          `Unable to read rrweb signing secret at ${secretPath}: ${error.message}`,
          { cause: error }
        );
      }

      if (Buffer.byteLength(secret) >= 32) {
        break;
      }

      Atomics.wait(
        new Int32Array(new SharedArrayBuffer(4)),
        0,
        0,
        10
      );
    }
  }

  if (Buffer.byteLength(secret) < 32) {
    throw new Error(
      `rrweb signing secret at ${secretPath} must contain at least 32 bytes`
    );
  }

  if (process.platform !== "win32") {
    fs.chmodSync(secretPath, 0o600);
  }

  return secret;
}

module.exports = getSigningSecret;
