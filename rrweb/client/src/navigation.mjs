export function navigationOriginFor(origin) {
  const url = new URL(origin);
  if (url.hostname.startsWith("www.")) {
    url.hostname = url.hostname.slice(4);
  }
  return url.origin;
}

export function originMatchesScope(destination, target) {
  if (destination.origin === target.origin) {
    return true;
  }
  const targetUrl = new URL(target.origin);
  const navigationUrl = new URL(target.navigationOrigin);
  return (
    targetUrl.hostname.startsWith("www.") &&
    destination.protocol === navigationUrl.protocol &&
    destination.port === navigationUrl.port &&
    destination.hostname === navigationUrl.hostname
  );
}

export function isGatewayRoutedUrl(value, gatewayOrigin) {
  try {
    const url = new URL(value, gatewayOrigin);
    return (
      url.origin === gatewayOrigin &&
      url.searchParams.has("warpgate-target")
    );
  } catch {
    return false;
  }
}

export function gatewayUrl(destination, target, gatewayOrigin) {
  const result = new URL(
    `${destination.pathname}${destination.search}${destination.hash}`,
    gatewayOrigin,
  );
  result.searchParams.delete("warpgate-host");
  result.searchParams.set("warpgate-target", target.name);
  if (destination.origin !== target.origin) {
    result.searchParams.set("warpgate-host", destination.host);
  }
  return result.href;
}
