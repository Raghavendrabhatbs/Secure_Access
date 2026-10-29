const express = require("express");
const cheerio = require("cheerio");
const getSigningSecret =
  require("../shared/signing-secret");

const app = express();

const PORT = 4000;

const RRWEB_SCRIPT =
  "http://localhost:3000/rrweb-recorder.js";

const RRWEB_SIGNING_SECRET =
  getSigningSecret();

const WARPGATE_TARGET =
  process.env.WARPGATE_TARGET ||
  "rrweb-test";


// ==================================================
// WARPGATE USER LOGGING
// ==================================================

app.use((req, res, next) => {

  console.log(
    "--------------------------------"
  );

  console.log(
    "SecureAccess username:",
    req.headers[
      "x-warpgate-username"
    ]
  );

  console.log(
    "Authentication type:",
    req.headers[
      "x-warpgate-authentication-type"
    ]
  );

  console.log(
    "--------------------------------"
  );

  next();

});


// ==================================================
// URL HELPERS
// ==================================================

function normalizeUrl(value) {

  if (
    !value ||
    typeof value !== "string"
  ) {
    return null;
  }


  let url =
    value.trim();


  if (
    !url.startsWith("http://") &&
    !url.startsWith("https://")
  ) {

    url =
      `https://${url}`;

  }


  try {

    return new URL(
      url
    ).href;

  } catch {

    return null;

  }

}


function resolveUrl(
  value,
  currentUrl
) {

  if (
    !value ||
    typeof value !== "string"
  ) {
    return null;
  }


  if (
    value.startsWith("#") ||
    value.startsWith("javascript:") ||
    value.startsWith("mailto:") ||
    value.startsWith("tel:") ||
    value.startsWith("data:")
  ) {

    return null;

  }


  try {

    return new URL(
      value,
      currentUrl
    ).href;

  } catch {

    return null;

  }

}


function makeProxyUrl(url) {

  return (
    `/proxy?url=${encodeURIComponent(
      url
    )}`
  );

}


function makeNewSessionProxyUrl(
  url
) {

  return (
    `${makeProxyUrl(url)}` +
    `&rrweb-new-session=1`
  );

}


function escapeHtmlAttribute(
  value
) {

  return String(
    value ?? ""
  )

    .replace(
      /&/g,
      "&amp;"
    )

    .replace(
      /"/g,
      "&quot;"
    )

    .replace(
      /</g,
      "&lt;"
    )

    .replace(
      />/g,
      "&gt;"
    );

}


function createRecordingToken(
  payload
) {
  const safePayload = {
    username:
      payload.username || "unknown",
    target:
      payload.target ||
      WARPGATE_TARGET,
    authenticationType:
      payload.authenticationType ||
      "unknown",
    expiresAt:
      Date.now() +
      60 * 60 * 1000,
  };

  const encodedPayload =
    Buffer.from(
      JSON.stringify(
        safePayload
      )
    ).toString(
      "base64url"
    );

  const signature =
    crypto
      .createHmac(
        "sha256",
        RRWEB_SIGNING_SECRET
      )
      .update(
        encodedPayload
      )
      .digest(
        "base64url"
      );

  return `${encodedPayload}.${signature}`;
}


// ==================================================
// RUNTIME NAVIGATION INTERCEPTOR
// ==================================================

function getNavigationInterceptor(
  currentUrl
) {

  const safeCurrentUrl =
    JSON.stringify(
      currentUrl
    );


  return `
<script>
(function () {

  const ORIGINAL_PAGE_URL =
    ${safeCurrentUrl};


  function shouldIgnore(value) {

    if (!value) {
      return true;
    }


    return (
      value.startsWith("#") ||
      value.startsWith("javascript:") ||
      value.startsWith("mailto:") ||
      value.startsWith("tel:") ||
      value.startsWith("data:")
    );

  }


  function isAlreadyProxied(value) {

    if (!value) {
      return false;
    }


    return (
      value.startsWith("/proxy?url=") ||
      value.startsWith("/open") ||
      value.startsWith("/@warpgate")
    );

  }


  function resolveDestination(value) {

    if (
      !value ||
      shouldIgnore(value) ||
      isAlreadyProxied(value)
    ) {

      return null;

    }


    try {

      return new URL(
        value,
        ORIGINAL_PAGE_URL
      ).href;

    } catch {

      return null;

    }

  }


  function makeProxyUrl(url) {

    return (
      "/proxy?url=" +
      encodeURIComponent(url)
    );

  }


  // ================================================
  // LINK CLICKS
  // ================================================

  document.addEventListener(
    "click",

    function (event) {

      const link =
        event.target.closest(
          "a[href]"
        );


      if (!link) {
        return;
      }


      const rawHref =
        link.getAttribute(
          "href"
        );


      if (
        !rawHref ||
        shouldIgnore(rawHref) ||
        isAlreadyProxied(rawHref)
      ) {

        return;

      }


      const destination =
        resolveDestination(
          rawHref
        );


      if (
        !destination ||
        (
          !destination.startsWith(
            "http://"
          )
          &&
          !destination.startsWith(
            "https://"
          )
        )
      ) {

        return;

      }


      event.preventDefault();

      event.stopPropagation();


      console.log(
        "[RRWeb Proxy] Navigation intercepted:",
        destination
      );


      window.location.href =
        makeProxyUrl(
          destination
        );

    },

    true
  );


  // ================================================
  // GET FORM SUBMISSIONS
  // ================================================

  document.addEventListener(
    "submit",

    function (event) {

      const form =
        event.target;


      if (
        !(
          form instanceof
          HTMLFormElement
        )
      ) {

        return;

      }


      const method =
        (
          form.method ||
          "GET"
        ).toUpperCase();


      if (
        method !== "GET"
      ) {

        return;

      }


      const rawAction =
        form.getAttribute(
          "action"
        )
        ||
        ORIGINAL_PAGE_URL;


      if (
        isAlreadyProxied(
          rawAction
        )
      ) {

        return;

      }


      const destination =
        resolveDestination(
          rawAction
        );


      if (!destination) {
        return;
      }


      event.preventDefault();

      event.stopPropagation();


      const target =
        new URL(
          destination
        );


      const formData =
        new FormData(
          form
        );


      for (
        const [key, value]
        of formData.entries()
      ) {

        target.searchParams.append(
          key,
          String(value)
        );

      }


      console.log(
        "[RRWeb Proxy] Form intercepted:",
        target.href
      );


      window.location.href =
        makeProxyUrl(
          target.href
        );

    },

    true
  );


  // ================================================
  // window.open(...)
  // ================================================

  const originalWindowOpen =
    window.open.bind(
      window
    );


  window.open =
    function (
      url,
      target,
      features
    ) {

      if (
        typeof url !== "string" ||
        shouldIgnore(url) ||
        isAlreadyProxied(url)
      ) {

        return originalWindowOpen(
          url,
          target,
          features
        );

      }


      const destination =
        resolveDestination(
          url
        );


      if (!destination) {

        return originalWindowOpen(
          url,
          target,
          features
        );

      }


      console.log(
        "[RRWeb Proxy] window.open intercepted:",
        destination
      );


      return originalWindowOpen(

        makeProxyUrl(
          destination
        ),

        target,

        features

      );

    };


  // ================================================
  // LINKS CREATED BY JAVASCRIPT
  // ================================================

  const observer =
    new MutationObserver(
      function () {

        document
          .querySelectorAll(
            "a[href]"
          )
          .forEach(
            function (link) {

              const href =
                link.getAttribute(
                  "href"
                );


              if (
                !href ||
                shouldIgnore(href) ||
                isAlreadyProxied(href)
              ) {

                return;

              }


              const destination =
                resolveDestination(
                  href
                );


              if (
                !destination ||
                (
                  !destination.startsWith(
                    "http://"
                  )
                  &&
                  !destination.startsWith(
                    "https://"
                  )
                )
              ) {

                return;

              }


              link.setAttribute(

                "href",

                makeProxyUrl(
                  destination
                )

              );

            }
          );

      }
    );


  observer.observe(
    document.documentElement,

    {
      childList: true,
      subtree: true,
    }
  );


  console.log(
    "[RRWeb Proxy] Navigation interceptor active"
  );

})();
</script>
`;

}


// ==================================================
// SRCSET REWRITING
// ==================================================

function rewriteSrcset(
  srcset,
  currentUrl
) {

  if (!srcset) {

    return srcset;

  }


  return srcset

    .split(",")

    .map(
      (part) => {

        const pieces =
          part
            .trim()
            .split(
              /\s+/
            );


        const destination =
          resolveUrl(
            pieces[0],
            currentUrl
          );


        if (!destination) {

          return part;

        }


        pieces[0] =
          makeProxyUrl(
            destination
          );


        return pieces.join(
          " "
        );

      }
    )

    .join(", ");

}


// ==================================================
// HTML REWRITING
// ==================================================

function rewriteHtml(
  html,
  currentUrl,
  warpgateContext
) {

  const $ =
    cheerio.load(
      html
    );


  // ------------------------------------------------
  // LINKS
  // ------------------------------------------------

  $("a[href]").each(
    (_, element) => {

      const destination =
        resolveUrl(

          $(element)
            .attr("href"),

          currentUrl

        );


      if (destination) {

        $(element).attr(

          "href",

          makeProxyUrl(
            destination
          )

        );

      }

    }
  );


  // ------------------------------------------------
  // IFRAMES
  // ------------------------------------------------

  $("iframe[src]").each(
    (_, element) => {

      const destination =
        resolveUrl(

          $(element)
            .attr("src"),

          currentUrl

        );


      if (destination) {

        $(element).attr(

          "src",

          makeProxyUrl(
            destination
          )

        );

      }

    }
  );


  // ------------------------------------------------
  // IMAGES / SOURCES
  // ------------------------------------------------

  $(
    "img[src], source[src]"
  ).each(
    (_, element) => {

      const destination =
        resolveUrl(

          $(element)
            .attr("src"),

          currentUrl

        );


      if (destination) {

        $(element).attr(

          "src",

          makeProxyUrl(
            destination
          )

        );

      }

    }
  );


  // ------------------------------------------------
  // SRCSET
  // ------------------------------------------------

  $("[srcset]").each(
    (_, element) => {

      $(element).attr(

        "srcset",

        rewriteSrcset(

          $(element)
            .attr("srcset"),

          currentUrl

        )

      );

    }
  );


  // ------------------------------------------------
  // STYLESHEETS / LINK RESOURCES
  // ------------------------------------------------

  $("link[href]").each(
    (_, element) => {

      const destination =
        resolveUrl(

          $(element)
            .attr("href"),

          currentUrl

        );


      if (destination) {

        $(element).attr(

          "href",

          makeProxyUrl(
            destination
          )

        );

      }

    }
  );


  // ------------------------------------------------
  // JAVASCRIPT
  // ------------------------------------------------

  $("script[src]").each(
    (_, element) => {

      const original =
        $(element)
          .attr("src");


      if (
        original ===
        RRWEB_SCRIPT
      ) {

        return;

      }


      const destination =
        resolveUrl(
          original,
          currentUrl
        );


      if (destination) {

        $(element).attr(

          "src",

          makeProxyUrl(
            destination
          )

        );

      }

    }
  );


  // ------------------------------------------------
  // GET FORMS
  // ------------------------------------------------

  $("form").each(
    (_, element) => {

      const method =
        (
          $(element)
            .attr("method")
          ||
          "GET"
        )
          .toUpperCase();


      if (
        method !== "GET"
      ) {

        return;

      }


      const originalAction =
        $(element)
          .attr("action")
        ||
        currentUrl;


      const destination =
        resolveUrl(
          originalAction,
          currentUrl
        );


      if (!destination) {

        return;

      }


      $(element).attr(
        "action",
        "/proxy"
      );


      $(element).prepend(
        `
        <input
          type="hidden"
          name="url"
          value="${escapeHtmlAttribute(
            destination
          )}"
        >
        `
      );

    }
  );


  // ------------------------------------------------
  // NAVIGATION INTERCEPTOR
  // ------------------------------------------------

  $("body").append(

    getNavigationInterceptor(
      currentUrl
    )

  );


  // ------------------------------------------------
  // RRWEB + WARPGATE USER INFORMATION
  // ------------------------------------------------

  const recordingToken =
    createRecordingToken({
      username:
        warpgateContext.username,
      target:
        warpgateContext.target,
      authenticationType:
        warpgateContext.authenticationType,
    });

  $("body").append(
    `
    <script

      src="${RRWEB_SCRIPT}"

      data-recording-token="${escapeHtmlAttribute(
        recordingToken
      )}"

      data-warpgate-username="${escapeHtmlAttribute(
        warpgateContext.username
      )}"

      data-warpgate-authentication-type="${escapeHtmlAttribute(
        warpgateContext.authenticationType
      )}"

      data-warpgate-target="${escapeHtmlAttribute(
        warpgateContext.target
      )}"

      data-upstream-url="${escapeHtmlAttribute(
        warpgateContext.pageUrl
      )}"

      data-new-session="${
        warpgateContext.newSession
          ? "true"
          : "false"
      }"

    ></script>
    `
  );


  return $.html();

}


// ==================================================
// CSS URL(...) REWRITING
// ==================================================

function rewriteCss(
  css,
  currentUrl
) {

  return css.replace(

    /url\((['"]?)(.*?)\1\)/gi,

    (
      match,
      quote,
      value
    ) => {

      if (
        !value ||
        value.startsWith(
          "data:"
        ) ||
        value.startsWith(
          "#"
        )
      ) {

        return match;

      }


      const destination =
        resolveUrl(
          value,
          currentUrl
        );


      if (!destination) {

        return match;

      }


      return (
        `url("${makeProxyUrl(
          destination
        )}")`
      );

    }

  );

}


// ==================================================
// RRWEB RECORDING BROWSER HOME PAGE
// ==================================================

app.get(
  "/",

  (req, res) => {

    res.send(`
<!DOCTYPE html>

<html lang="en">

<head>

  <meta charset="UTF-8" />

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  />

  <title>
    RRWeb Recording Browser
  </title>


  <style>

    * {
      box-sizing: border-box;
    }


    :root {

      --bg: #0f141b;

      --panel: #171c24;

      --panel-soft: #1f2630;

      --border: #2c3541;

      --text: #f4f6f8;

      --muted: #8d97a5;

      --accent: #4f8cff;

      --accent-hover: #3f7fe9;

    }


    body {

      margin: 0;

      min-height: 100vh;

      font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

      background:

        radial-gradient(

          circle at top left,

          rgba(
            79,
            140,
            255,
            0.12
          ),

          transparent 34%

        ),

        var(--bg);

      color:
        var(--text);

      display: flex;

      flex-direction: column;

    }


    header {

      height: 68px;

      display: flex;

      align-items: center;

      padding:
        0 28px;

      border-bottom:
        1px solid
        var(--border);

      background:
        rgba(
          23,
          28,
          36,
          0.92
        );

      backdrop-filter:
        blur(10px);

    }


    .brand {

      display: flex;

      align-items: center;

      gap: 11px;

    }


    .brand-logo {

      width: 36px;

      height: 36px;

      border-radius:
        9px;

      display: flex;

      align-items: center;

      justify-content: center;

      background:
        #24417a;

      color:
        #7caeff;

      font-size:
        13px;

      font-weight:
        800;

    }


    .brand h1 {

      margin: 0;

      font-size:
        17px;

      font-weight:
        700;

    }


    main {

      flex: 1;

      display: flex;

      align-items: center;

      justify-content: center;

      padding:
        40px
        20px
        80px;

    }


    .hero {

      width:
        min(
          800px,
          100%
        );

      text-align:
        center;

    }


    .hero h2 {

      margin: 0;

      font-size:
        clamp(
          36px,
          5vw,
          56px
        );

      line-height:
        1.05;

      letter-spacing:
        -1.6px;

    }


    .hero p {

      max-width:
        610px;

      margin:
        20px
        auto
        0;

      color:
        var(--muted);

      font-size:
        14px;

      line-height:
        1.7;

    }


    .search-card {

      margin-top:
        36px;

      padding:
        18px;

      display: flex;

      gap: 10px;

      background:
        var(--panel);

      border:
        1px solid
        var(--border);

      border-radius:
        14px;

      box-shadow:
        0
        18px
        45px
        rgba(
          0,
          0,
          0,
          0.26
        );

    }


    .url-input {

      flex: 1;

      height:
        50px;

      padding:
        0 15px;

      border:
        1px solid
        var(--border);

      border-radius:
        9px;

      outline:
        none;

      background:
        var(--panel-soft);

      color:
        var(--text);

      font-size:
        14px;

    }


    .url-input::placeholder {

      color:
        #687484;

    }


    .url-input:focus {

      border-color:
        var(--accent);

      box-shadow:
        0
        0
        0
        3px
        rgba(
          79,
          140,
          255,
          0.12
        );

    }


    .open-button {

      min-width:
        120px;

      height:
        50px;

      border:
        none;

      border-radius:
        9px;

      background:
        var(--accent);

      color:
        white;

      font-size:
        13px;

      font-weight:
        700;

      cursor:
        pointer;

      transition:
        background
        120ms ease,
        transform
        120ms ease;

    }


    .open-button:hover {

      background:
        var(
          --accent-hover
        );

      transform:
        translateY(
          -1px
        );

    }


    .examples {

      margin-top:
        18px;

      display: flex;

      align-items:
        center;

      justify-content:
        center;

      flex-wrap:
        wrap;

      gap:
        8px;

      color:
        var(--muted);

      font-size:
        10px;

    }


    .example-link {

      padding:
        6px 10px;

      border:
        1px solid
        var(--border);

      border-radius:
        7px;

      background:
        var(--panel);

      color:
        var(--muted);

      cursor:
        pointer;

    }


    .example-link:hover {

      color:
        var(--text);

      background:
        var(--panel-soft);

      border-color:
        #3b4654;

    }


    footer {

      padding:
        18px;

      text-align:
        center;

      color:
        var(--muted);

      font-size:
        9px;

    }


    @media (
      max-width: 700px
    ) {

      header {

        padding:
          0 18px;

      }


      .search-card {

        flex-direction:
          column;

      }


      .open-button {

        width:
          100%;

      }

    }

  </style>

</head>


<body>


  <header>

    <div class="brand">

      <div class="brand-logo">
        rr
      </div>

      <h1>
        RRWeb Recording Browser
      </h1>

    </div>

  </header>


  <main>

    <section class="hero">


      <h2>

        Open a website.

        <br />

        We record the session.

      </h2>


      <p>

        Open websites through an authorized HTTP target in
        SecureAccess. This standalone proxy does not fetch arbitrary
        URLs or provide a route around SecureAccess authorization.

      </p>


      <form

        class="search-card"

        action="/open"

        method="GET"

      >


        <input

          id="url-input"

          class="url-input"

          name="url"

          type="text"

          placeholder="https://example.com"

          autocomplete="off"

          required

        />


        <button

          class="open-button"

          type="submit"

        >

          Open website

        </button>


      </form>


      <div class="examples">


        <span>
          Try:
        </span>


        <button

          class="example-link"

          type="button"

          data-url="https://wikipedia.org"

        >

          Wikipedia

        </button>


        <button

          class="example-link"

          type="button"

          data-url="https://example.com"

        >

          Example

        </button>


        <button

          class="example-link"

          type="button"

          data-url="https://news.ycombinator.com"

        >

          Hacker News

        </button>


        <button

          class="example-link"

          type="button"

          data-url="https://developer.mozilla.org"

        >

          MDN

        </button>


        <button

          class="example-link"

          type="button"

          data-url="https://httpbin.org"

        >

          HTTPBin

        </button>


      </div>


    </section>

  </main>


  <footer>

    rrweb session recording environment

  </footer>


  <script>

    const urlInput =
      document.getElementById(
        "url-input"
      );


    document

      .querySelectorAll(
        "[data-url]"
      )

      .forEach(
        (button) => {

          button.addEventListener(

            "click",

            () => {

              urlInput.value =
                button.dataset.url;

              urlInput.focus();

            }

          );

        }
      );

  </script>


</body>

</html>

    `);

  }

);


// ==================================================
// OPEN WEBSITE
// THIS STARTS A NEW RRWEB SESSION
// ==================================================

app.get(
  "/open",

  (req, res) => {
    return res
      .status(403)
      .send("Open this site through an HTTP target authorized for your SecureAccess account.");

  }

);


// ==================================================
// DYNAMIC PROXY
// ==================================================

app.use(
  "/proxy",
  (_req, res) =>
    res
      .status(403)
      .send("Arbitrary URL proxying is disabled; use an authorized SecureAccess HTTP target."),
);

app.get(
  "/proxy",

  async (
    req,
    res
  ) => {

    let targetUrl =
      req.query.url;


    if (!targetUrl) {

      return res
        .status(400)
        .send(
          "Missing url parameter"
        );

    }


    targetUrl =
      normalizeUrl(
        targetUrl
      );


    if (!targetUrl) {

      return res
        .status(400)
        .send(
          "Invalid target URL"
        );

    }


    // ------------------------------------------------
    // NEW SESSION FLAG
    // ------------------------------------------------

    const isNewSession =
      req.query[
        "rrweb-new-session"
      ] === "1";


    // ------------------------------------------------
    // WARPGATE IDENTITY
    // ------------------------------------------------

    const warpgateUsername =
      req.headers[
        "x-warpgate-username"
      ]
      ||
      "unknown";


    const warpgateAuthenticationType =
      req.headers[
        "x-warpgate-authentication-type"
      ]
      ||
      "unknown";

    const warpgateTarget =
      req.headers[
        "x-warpgate-target"
      ]
      ||
      WARPGATE_TARGET;


    console.log(
      "Recording user:",
      warpgateUsername
    );


    // ------------------------------------------------
    // BUILD REAL DESTINATION URL
    // ------------------------------------------------

    const destination =
      new URL(
        targetUrl
      );


    for (
      const [key, value]
      of Object.entries(
        req.query
      )
    ) {


      // These belong only to our proxy.
      if (
        key === "url"
        ||
        key === "rrweb-new-session"
      ) {

        continue;

      }


      if (
        Array.isArray(
          value
        )
      ) {

        for (
          const item
          of value
        ) {

          destination
            .searchParams
            .append(
              key,
              item
            );

        }

      } else {

        destination
          .searchParams
          .append(
            key,
            value
          );

      }

    }


    console.log(
      "Proxying:",
      destination.href
    );


    try {


      // ------------------------------------------------
      // UPSTREAM REQUEST HEADERS
      // ------------------------------------------------

      const headers = {

        "User-Agent":

          req.headers[
            "user-agent"
          ]

          ||

          "Mozilla/5.0",


        "Accept":

          req.headers.accept

          ||

          "*/*",


        "Accept-Language":

          req.headers[
            "accept-language"
          ]

          ||

          "en-US,en;q=0.9",

      };


      // ------------------------------------------------
      // FETCH WEBSITE
      // ------------------------------------------------

      const response =
        await fetch(

          destination.href,

          {

            method:
              "GET",

            redirect:
              "follow",

            headers,

          }

        );


      const finalUrl =
        response.url
        ||
        destination.href;


      const contentType =
        response.headers.get(
          "content-type"
        )
        ||
        "";


      // =================================================
      // HTML RESPONSE
      // =================================================

      if (
        contentType.includes(
          "text/html"
        )
      ) {


        let html =
          await response.text();


        const warpgateContext = {

          username:
            String(
              warpgateUsername
            ),

          authenticationType:
            String(
              warpgateAuthenticationType
            ),

          target:
            String(
              warpgateTarget
            ),

          pageUrl:
            finalUrl,

          newSession:
            isNewSession,

        };


        html =
          rewriteHtml(

            html,

            finalUrl,

            warpgateContext

          );


        console.log(
          "Injected rrweb into:",
          finalUrl
        );


        res.status(
          response.status
        );


        res.set(

          "Content-Type",

          "text/html; charset=utf-8"

        );


        return res.send(
          html
        );

      }


      // =================================================
      // CSS RESPONSE
      // =================================================

      if (
        contentType.includes(
          "text/css"
        )
      ) {


        let css =
          await response.text();


        css =
          rewriteCss(
            css,
            finalUrl
          );


        res.status(
          response.status
        );


        res.set(
          "Content-Type",
          contentType
        );


        return res.send(
          css
        );

      }


      // =================================================
      // OTHER FILE TYPES
      // =================================================

      const buffer =
        Buffer.from(

          await response
            .arrayBuffer()

        );


      res.status(
        response.status
      );


      if (contentType) {

        res.set(
          "Content-Type",
          contentType
        );

      }


      return res.send(
        buffer
      );


    } catch (error) {


      console.error(
        "Proxy error:",
        error
      );


      return res

        .status(500)

        .send(
          `Proxy error: ${error.message}`
        );

    }

  }

);


// ==================================================
// START PROXY
// ==================================================

app.listen(
  PORT,

  () => {

    console.log(
      `Dynamic RRWeb proxy running on http://localhost:${PORT}`
    );

  }

);