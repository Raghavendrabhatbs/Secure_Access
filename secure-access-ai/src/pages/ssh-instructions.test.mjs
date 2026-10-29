import assert from "node:assert/strict";
import test from "node:test";

import { createSshInstructionCommands } from "./ssh-instructions.js";

test("creates SSH and SCP instructions for the selected target", () => {
  assert.deepEqual(
    createSshInstructionCommands({
      username: "Raghu",
      targetName: "ssh-demo",
      gatewayHost: "172.25.117.183",
      port: 2222,
    }),
    {
      ssh: 'ssh "Raghu:ssh-demo@172.25.117.183" -p 2222',
      scp: 'scp -o "User=`"Raghu:ssh-demo`"" -P 2222 local-file "172.25.117.183:remote-file"',
      endpoint: "172.25.117.183:2222",
    },
  );
});

test("shell-escapes instruction values and rejects missing SSH endpoints", () => {
  assert.equal(
    createSshInstructionCommands({
      username: "user'one",
      targetName: "prod server",
      gatewayHost: "gateway.example",
      port: "2222",
    }).ssh,
    'ssh "user\'one:prod server@gateway.example" -p 2222',
  );
  assert.equal(
    createSshInstructionCommands({
      username: 'user"$HOME',
      targetName: "prod`server",
      gatewayHost: "gateway.example",
      port: 2222,
    }).ssh,
    'ssh "user`"`$HOME:prod``server@gateway.example" -p 2222',
  );
  assert.throws(
    () =>
      createSshInstructionCommands({
        username: "admin",
        targetName: "ssh-demo",
        gatewayHost: "localhost",
        port: undefined,
      }),
    /not available/,
  );
});
