import warpgateTheme from "../styles/WarpgateEmbeddedTheme.css?inline";

export default function WarpgateAdminFrame({ className, src, title }) {
  function applySecureAccessTheme(event) {
    const frameDocument = event.currentTarget.contentDocument;
    if (!frameDocument?.head) {
      console.error("Unable to apply SecureAccess styling to the gateway page.");
      return;
    }

    let themeStyle = frameDocument.getElementById("secure-access-warpgate-theme");
    if (!themeStyle) {
      themeStyle = frameDocument.createElement("style");
      themeStyle.id = "secure-access-warpgate-theme";
      frameDocument.head.append(themeStyle);
    }
    themeStyle.textContent = warpgateTheme;
  }

  return (
    <iframe
      className={className}
      onLoad={applySecureAccessTheme}
      src={src}
      title={title}
    />
  );
}
