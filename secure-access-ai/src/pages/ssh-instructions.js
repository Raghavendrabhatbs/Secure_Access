function quotePowerShell(value) {
  return `"${String(value).replace(/[`"$]/g, (character) => `\`${character}`)}"`;
}

export function createSshInstructionCommands({
  username,
  targetName,
  gatewayHost,
  port,
}) {
  if (
    typeof username !== "string" ||
    !username.trim() ||
    typeof targetName !== "string" ||
    !targetName.trim() ||
    typeof gatewayHost !== "string" ||
    !gatewayHost.trim() ||
    (typeof port !== "number" && typeof port !== "string") ||
    !/^\d+$/.test(String(port)) ||
    Number(port) < 1 ||
    Number(port) > 65535
  ) {
    throw new Error("SSH access instructions are not available for this target.");
  }

  const normalizedPort = Number(port);
  const endpoint = `${gatewayHost}:${normalizedPort}`;
  const selector = `${username}:${targetName}@${gatewayHost}`;
  return {
    ssh: `ssh ${quotePowerShell(selector)} -p ${normalizedPort}`,
    scp: `scp -o ${quotePowerShell(`User="${username}:${targetName}"`)} -P ${normalizedPort} local-file ${quotePowerShell(`${gatewayHost}:remote-file`)}`,
    endpoint,
  };
}
