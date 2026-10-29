import assert from "node:assert/strict";
import test from "node:test";

import {
  gatewayUrl,
  isGatewayRoutedUrl,
  navigationOriginFor,
  originMatchesScope,
} from "../src/navigation.mjs";

const target = {
  name: "web-demo",
  origin: "https://www.wikipedia.org",
  navigationOrigin: navigationOriginFor("https://www.wikipedia.org"),
};

test("allows only the configured origin and its bare-domain alias", () => {
  for (const url of [
    "https://www.wikipedia.org/",
    "https://wikipedia.org/wiki/Main_Page",
  ]) {
    assert.equal(originMatchesScope(new URL(url), target), true, url);
  }
  for (const url of [
    "https://en.wikipedia.org/wiki/Artificial_intelligence",
    "https://admin.wikipedia.org/",
  ]) {
    assert.equal(originMatchesScope(new URL(url), target), false, url);
  }
});

test("rejects unconfigured subdomains, lookalike domains, protocol changes, and ports", () => {
  for (const url of [
    "https://www.wikipedia.org.attacker.example/",
    "https://notwikipedia.org/",
    "http://wikipedia.org/",
    "https://wikipedia.org:444/",
  ]) {
    assert.equal(originMatchesScope(new URL(url), target), false, url);
  }
});

test("routes the bare-domain alias through the configured target", () => {
  const absolute = new URL(
    "https://wikipedia.org/wiki/Artificial_Intelligence?q=AI#History",
  );
  const relative = new URL(
    "../wiki/Artificial_Intelligence?search=AI#History",
    "https://wikipedia.org/w/index.php",
  );

  assert.equal(
    gatewayUrl(absolute, target, "https://gateway.test"),
    "https://gateway.test/wiki/Artificial_Intelligence?q=AI&warpgate-target=web-demo&warpgate-host=wikipedia.org#History",
  );
  assert.equal(
    gatewayUrl(relative, target, "https://gateway.test"),
    "https://gateway.test/wiki/Artificial_Intelligence?search=AI&warpgate-target=web-demo&warpgate-host=wikipedia.org#History",
  );
});

test("routes a subdomain only through its separately authorized target", () => {
  const englishTarget = {
    name: "wikipedia-en",
    origin: "https://en.wikipedia.org",
    navigationOrigin: "https://en.wikipedia.org",
  };
  const destination = new URL(
    "https://en.wikipedia.org/wiki/Artificial_Intelligence?q=AI#History",
  );

  assert.equal(originMatchesScope(destination, target), false);
  assert.equal(originMatchesScope(destination, englishTarget), true);
  assert.equal(
    gatewayUrl(destination, englishTarget, "https://gateway.test"),
    "https://gateway.test/wiki/Artificial_Intelligence?q=AI&warpgate-target=wikipedia-en#History",
  );
});

test("does not preserve a client-supplied upstream host override", () => {
  const destination = new URL(
    "https://www.wikipedia.org/?warpgate-host=attacker.example&query=ai",
  );
  assert.equal(
    gatewayUrl(destination, target, "https://gateway.test"),
    "https://gateway.test/?query=ai&warpgate-target=web-demo",
  );
});

test("recognizes same-origin Warpgate URLs without reinterpreting their upstream host", () => {
  assert.equal(
    isGatewayRoutedUrl(
      "/wiki/Article?warpgate-target=web-demo&warpgate-host=en.wikipedia.org",
      "https://gateway.test",
    ),
    true,
  );
  assert.equal(
    isGatewayRoutedUrl(
      "https://attacker.test/wiki?warpgate-target=web-demo",
      "https://gateway.test",
    ),
    false,
  );
  assert.equal(
    isGatewayRoutedUrl("/wiki/Article", "https://gateway.test"),
    false,
  );
});
