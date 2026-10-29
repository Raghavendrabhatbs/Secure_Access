import rrwebPlayer from "rrweb-player";
import "rrweb-player/dist/style.css";

const SERVER_URL = "";


const root =
  document.documentElement;

const sessionSelect =
  document.getElementById("session-select");

const refreshButton =
  document.getElementById("refresh-button");

const themeButton =
  document.getElementById("theme-button");

const playerContainer =
  document.getElementById("player");

const replayStage =
  document.getElementById("replay-stage");

const emptyState =
  document.getElementById("empty-state");

const eventsList =
  document.getElementById("events-list");

const eventTotal =
  document.getElementById("event-total");

const eventCount =
  document.getElementById("event-count");

const currentTime =
  document.getElementById("current-time");

const footerDuration =
  document.getElementById("footer-duration");

const sessionId =
  document.getElementById("session-id");

const headerSession =
  document.getElementById("header-session");

const headerDate =
  document.getElementById("header-date");

const headerDuration =
  document.getElementById("header-duration");

const centerFeedback =
  document.getElementById("center-feedback");


let playerInstance = null;
let currentEvents = [];
let eventIndexMap = new Map();
let activeEventIndex = -1;

let currentPlaybackTime = 0;
let totalDuration = 0;

let isPlaying = false;

let feedbackTimer = null;


// --------------------------------------------------
// THEME
// --------------------------------------------------

function applyTheme(theme) {

  root.setAttribute(
    "data-theme",
    theme
  );

  themeButton.textContent =
    theme === "dark"
      ? "Light"
      : "Dark";

  localStorage.setItem(
    "rrweb-player-theme",
    theme
  );

}


applyTheme(
  localStorage.getItem(
    "rrweb-player-theme"
  ) || "dark"
);


themeButton.addEventListener(
  "click",
  () => {

    const current =
      root.getAttribute(
        "data-theme"
      );

    applyTheme(
      current === "dark"
        ? "light"
        : "dark"
    );

  }
);


// --------------------------------------------------
// SESSION HELPERS
// --------------------------------------------------

function getSessionTimestamp(file) {

  const match =
    file.match(
      /session-(\d+)/
    );

  return match
    ? Number(match[1])
    : 0;

}


function sessionDisplayName(file) {

  const timestamp =
    getSessionTimestamp(file);

  if (!timestamp) {
    return file;
  }

  const date =
    new Date(timestamp);


  const datePart =
    date.toLocaleDateString(
      undefined,
      {
        day: "2-digit",
        month: "short",
        year: "numeric",
      }
    );


  const timePart =
    date.toLocaleTimeString(
      undefined,
      {
        hour: "2-digit",
        minute: "2-digit",
      }
    );


  const shortId =
    String(timestamp)
      .slice(-6);


  return `${datePart} • ${timePart} • #${shortId}`;

}


function shortSessionName(file) {

  const timestamp =
    getSessionTimestamp(file);

  if (!timestamp) {
    return file;
  }

  return new Date(
    timestamp
  ).toLocaleTimeString(
    undefined,
    {
      hour: "2-digit",
      minute: "2-digit",
    }
  );

}


function formatDate(timestamp) {

  if (!timestamp) {
    return "—";
  }

  return new Date(
    timestamp
  ).toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short",
    }
  );

}


function formatClock(ms) {

  const value =
    Math.max(
      0,
      Number(ms) || 0
    );

  const seconds =
    Math.floor(
      value / 1000
    );

  const minutes =
    Math.floor(
      seconds / 60
    );

  return (
    String(minutes)
      .padStart(2, "0")
    +
    ":"
    +
    String(
      seconds % 60
    ).padStart(2, "0")
  );

}

async function loadSessions() {

  try {

    const response =
      await fetch(
        `${SERVER_URL}/api/sessions`,
        {
      credentials: "include",
    }
      );


    if (!response.ok) {

      throw new Error(
        `Unable to load sessions: ${response.status}`
      );

    }


    const sessions =
      await response.json();


    const oldValue =
      sessionSelect.value;


    sessionSelect.innerHTML = `
      <option value="">
        Select a recorded session
      </option>
    `;


    // --------------------------------------------------
    // GROUP RECORDINGS BY WARPGATE USER
    // --------------------------------------------------

    const sessionsByUser =
      new Map();


    sessions.forEach(
      (session) => {

        const username =
          session.username
          ||
          "unknown";


        if (
          !sessionsByUser.has(
            username
          )
        ) {

          sessionsByUser.set(
            username,
            []
          );

        }


        sessionsByUser
          .get(
            username
          )
          .push(
            session
          );

      }
    );


    // --------------------------------------------------
    // SORT USERS
    // --------------------------------------------------

    const usernames =
      Array.from(
        sessionsByUser.keys()
      )
      .sort(
        (a, b) =>
          a.localeCompare(
            b
          )
      );


    // --------------------------------------------------
    // CREATE ONE OPTGROUP PER USER
    // --------------------------------------------------

    usernames.forEach(
      (username) => {

        const group =
          document.createElement(
            "optgroup"
          );


        group.label =
          `${username} — ${sessionsByUser.get(username).length} recording(s)`;


        const userSessions =
          sessionsByUser.get(
            username
          );


        // Newest first inside each user
        userSessions.sort(
          (a, b) => {

            const aTime =
              new Date(
                a.startedAt || 0
              ).getTime();


            const bTime =
              new Date(
                b.startedAt || 0
              ).getTime();


            return (
              bTime - aTime
            );

          }
        );


        userSessions.forEach(
          (session) => {

            const option =
              document.createElement(
                "option"
              );


            option.value =
              session.file;


            const startedAt =
              session.startedAt
                ? new Date(
                    session.startedAt
                  )
                : null;


            let dateLabel =
              sessionDisplayName(
                session.file
              );


            if (
              startedAt &&
              !Number.isNaN(
                startedAt.getTime()
              )
            ) {

              dateLabel =
                startedAt.toLocaleString(
                  undefined,
                  {
                    day:
                      "2-digit",

                    month:
                      "short",

                    year:
                      "numeric",

                    hour:
                      "2-digit",

                    minute:
                      "2-digit",
                  }
                );

            }


            const eventLabel =
              Number(
                session.eventCount
                ||
                0
              )
                .toLocaleString();


            option.textContent =
              `${dateLabel} • ${eventLabel} events`;


            /*
             * Metadata is also kept on the option
             * in case we want to show it elsewhere
             * in the UI later.
             */
            option.dataset.username =
              session.username
              ||
              "unknown";


            option.dataset.target =
              session.target
              ||
              "unknown";


            group.appendChild(
              option
            );

          }
        );


        sessionSelect.appendChild(
          group
        );

      }
    );


    // --------------------------------------------------
    // RESTORE PREVIOUS SELECTION
    // --------------------------------------------------

    const stillExists =
      sessions.some(
        (session) =>
          session.file
          ===
          oldValue
      );


    if (
      oldValue &&
      stillExists
    ) {

      sessionSelect.value =
        oldValue;

    }


    if (
      sessions.length === 0
    ) {

      const option =
        document.createElement(
          "option"
        );


      option.disabled =
        true;


      option.textContent =
        "No recordings available";


      sessionSelect.appendChild(
        option
      );

    }

  } catch (error) {

    console.error(
      "Unable to load recordings:",
      error
    );


    sessionSelect.innerHTML = `
      <option value="">
        Unable to load recordings
      </option>
    `;

  }

}

// --------------------------------------------------
// EVENT DESCRIPTION
// --------------------------------------------------

function describeEvent(event) {

  if (
    event.type === 2
  ) {
    return {
      title: "Page snapshot",
      subtitle: "DOM snapshot",
      icon: "▣",
      className: "event-dom",
    };
  }


  if (
    event.type === 4
  ) {
    return {
      title: "Page metadata",
      subtitle: "Session information",
      icon: "◉",
      className: "event-page",
    };
  }


  if (
    event.type === 3 &&
    event.data
  ) {

    const source =
      event.data.source;


    if (source === 0) {
      return {
        title: "DOM updated",
        subtitle: "Mutation",
        icon: "◇",
        className: "event-dom",
      };
    }


    if (source === 1) {

      const positions =
        event.data.positions;

      if (
        Array.isArray(positions) &&
        positions.length
      ) {

        const p =
          positions[
            positions.length - 1
          ];

        return {
          title:
            `Mouse (${p.x}, ${p.y})`,
          subtitle:
            "Pointer movement",
          icon:
            "↗",
          className:
            "event-move",
        };

      }

    }


    if (source === 2) {

      const names = {
        0: "Mouse up",
        1: "Mouse down",
        2: "Click",
        3: "Context menu",
        4: "Double click",
        5: "Focus",
        6: "Blur",
      };

      const title =
        names[
          event.data.type
        ] ||
        "Interaction";

      return {
        title,
        subtitle:
          event.data.id
            ? `Element #${event.data.id}`
            : "User interaction",
        icon:
          title === "Click"
            ? "●"
            : "○",
        className:
          "event-click",
      };

    }


    if (source === 3) {

      return {
        title:
          `Scroll ${event.data.y || 0}px`,
        subtitle:
          "Viewport movement",
        icon:
          "↕",
        className:
          "event-scroll",
      };

    }


    if (source === 5) {

      let text =
        event.data.text;

      if (
        typeof text === "string" &&
        text.length > 24
      ) {
        text =
          text.slice(
            0,
            24
          ) + "…";
      }

      return {
        title:
          text
            ? `Input "${text}"`
            : "Input changed",
        subtitle:
          "Form input",
        icon:
          "⌨",
        className:
          "event-input",
      };

    }

  }


  return {
    title:
      `Event ${event.type}`,
    subtitle:
      "Recorded event",
    icon:
      "•",
    className:
      "event-generic",
  };

}


// --------------------------------------------------
// EVENTS SIDEBAR
// --------------------------------------------------

function renderEventList(events) {

  eventsList.innerHTML =
    "";

  eventIndexMap =
    new Map();

  activeEventIndex =
    -1;


  const start =
    events[0].timestamp;


  events.forEach(
    (event, index) => {

      eventIndexMap.set(
        event,
        index
      );


      const info =
        describeEvent(
          event
        );


      const row =
        document.createElement(
          "div"
        );


      row.className =
        "event-row";


      row.dataset.eventIndex =
        index;


      const relative =
        event.timestamp
        -
        start;


      row.innerHTML = `
        <div class="event-time">
          ${formatClock(relative)}
        </div>

        <div
          class="event-symbol ${info.className}"
        >
          ${escapeHtml(info.icon)}
        </div>

        <div class="event-content">

          <div class="event-title">
            ${escapeHtml(info.title)}
          </div>

          <div class="event-subtitle">
            ${escapeHtml(info.subtitle)}
          </div>

        </div>
      `;


      row.addEventListener(
        "click",
        () => {

          if (!playerInstance) {
            return;
          }

          currentPlaybackTime =
            relative;


          playerInstance.goto(
            relative,
            false
          );


          isPlaying =
            false;


          highlightEvent(
            index,
            true
          );

        }
      );


      eventsList.appendChild(
        row
      );

    }
  );


  eventTotal.textContent =
    events.length;

}


// --------------------------------------------------
// EVENT HIGHLIGHT
// --------------------------------------------------

function highlightEvent(
  index,
  smooth = false
) {

  const previous =
    eventsList.querySelector(
      ".event-row.active"
    );


  if (previous) {
    previous.classList.remove(
      "active"
    );
  }


  const row =
    eventsList.querySelector(
      `[data-event-index="${index}"]`
    );


  if (!row) {
    return;
  }


  row.classList.add(
    "active"
  );


  activeEventIndex =
    index;


  row.scrollIntoView({
    block:
      "nearest",

    behavior:
      smooth
        ? "smooth"
        : "auto",
  });

}


function findEventIndex(event) {

  if (
    eventIndexMap.has(
      event
    )
  ) {
    return eventIndexMap.get(
      event
    );
  }


  return currentEvents.findIndex(
    (item) =>
      item.timestamp
      ===
      event?.timestamp

      &&

      item.type
      ===
      event?.type
  );

}


// --------------------------------------------------
// PLAYBACK HELPERS
// --------------------------------------------------

function showFeedback(text) {

  centerFeedback.textContent =
    text;


  centerFeedback.classList.add(
    "visible"
  );


  clearTimeout(
    feedbackTimer
  );


  feedbackTimer =
    setTimeout(
      () => {

        centerFeedback.classList.remove(
          "visible"
        );

      },
      450
    );

}


function togglePlayback() {

  if (!playerInstance) {
    return;
  }


  playerInstance.toggle();


  isPlaying =
    !isPlaying;


  showFeedback(
    isPlaying
      ? "▶"
      : "Ⅱ"
  );

}


function seekBy(milliseconds) {

  if (!playerInstance) {
    return;
  }


  const replayer =
    playerInstance.getReplayer();


  /*
   * getCurrentTime() is provided by rrweb's
   * underlying Replayer.
   */
  let now =
    replayer.getCurrentTime();


  if (
    !Number.isFinite(now)
  ) {
    now =
      currentPlaybackTime;
  }


  const target =
    Math.max(
      0,
      Math.min(
        totalDuration,
        now + milliseconds
      )
    );


  currentPlaybackTime =
    target;


  /*
   * goto(time, play) lets us preserve
   * whether playback was running.
   */
  playerInstance.goto(
    target,
    isPlaying
  );


  currentTime.textContent =
    formatClock(
      target
    );


  showFeedback(
    milliseconds > 0
      ? "+3"
      : "−3"
  );

}


// --------------------------------------------------
// CLICK PLAYER LIKE YOUTUBE
// --------------------------------------------------

replayStage.addEventListener(
  "click",
  (event) => {

    if (!playerInstance) {
      return;
    }


    /*
     * Do not hijack clicks on rrweb's
     * built-in controls.
     */
    if (
      event.target.closest(
        ".rr-controller"
      )
      ||
      event.target.closest(
        "button"
      )
      ||
      event.target.closest(
        "input"
      )
      ||
      event.target.closest(
        "select"
      )
    ) {
      return;
    }


    const rrPlayer =
      playerContainer.querySelector(
        ".rr-player"
      );


    if (!rrPlayer) {
      return;
    }


    const rect =
      rrPlayer.getBoundingClientRect();


    /*
     * Ignore clicks outside the actual
     * player.
     */
    if (
      event.clientX < rect.left ||
      event.clientX > rect.right ||
      event.clientY < rect.top ||
      event.clientY > rect.bottom
    ) {
      return;
    }


    const x =
      event.clientX
      -
      rect.left;


    const ratio =
      x / rect.width;


    /*
     * YouTube-style zones:
     *
     * left third   -> back 3 sec
     * middle third -> play/pause
     * right third  -> forward 3 sec
     */
    if (
      ratio < 0.33
    ) {

      seekBy(
        -3000
      );

      return;

    }


    if (
      ratio > 0.67
    ) {

      seekBy(
        3000
      );

      return;

    }


    togglePlayback();

  }
);


// --------------------------------------------------
// HTML ESCAPE
// --------------------------------------------------

function escapeHtml(value) {

  const div =
    document.createElement(
      "div"
    );

  div.textContent =
    String(
      value ?? ""
    );

  return div.innerHTML;

}


// --------------------------------------------------
// REPLAY
// --------------------------------------------------

async function replaySession(file) {

  if (!file) {
    return;
  }


  emptyState.style.display =
    "none";


  const response =
    await fetch(
      `${SERVER_URL}/api/sessions/${encodeURIComponent(
        file
      )}`,
    {
      credentials: "include",
    }
    );


  const events =
    await response.json();


  if (
    !Array.isArray(events) ||
    !events.length
  ) {

    playerContainer.innerHTML =
      "Recording contains no events.";

    return;

  }


  events.sort(
    (a, b) =>
      a.timestamp
      -
      b.timestamp
  );


  currentEvents =
    events;


  const first =
    events[0].timestamp;


  const last =
    events[
      events.length - 1
    ].timestamp;


  totalDuration =
    last - first;


  currentPlaybackTime =
    0;


  isPlaying =
    false;


  headerSession.textContent =
    shortSessionName(
      file
    );


  headerDate.textContent =
    formatDate(
      first
    );


  headerDuration.textContent =
    formatClock(
      totalDuration
    );


  eventCount.textContent =
    events.length;


  footerDuration.textContent =
    formatClock(
      totalDuration
    );


  currentTime.textContent =
    "00:00";


  sessionId.textContent =
    `#${String(
      getSessionTimestamp(
        file
      )
    ).slice(-6)}`;


  renderEventList(
    events
  );


  playerContainer.innerHTML =
    "";


  /*
   * Smaller dimensions fix the issue where
   * the rrweb controller was hidden underneath
   * our footer.
   */
  playerInstance =
    new rrwebPlayer({

      target:
        playerContainer,

      props: {

        events,

        autoPlay:
          false,

        showController:
          true,

        width:
          760,

        height:
          428,

        speedOption: [
          1,
          2,
          4,
          8,
        ],

      },

    });


  const replayer =
    playerInstance
      .getReplayer();


  /*
   * Highlight events in real time.
   */
  replayer.on(
    "event-cast",
    (event) => {

      const index =
        findEventIndex(
          event
        );


      if (
        index !== -1
      ) {

        highlightEvent(
          index
        );

      }

    }
  );


  /*
   * Update current-time display.
   */
  playerInstance.addEventListener(
    "ui-update-current-time",
    (event) => {

      const payload =
        event?.detail?.payload
        ??
        event?.payload
        ??
        event?.detail
        ??
        0;


      const value =
        typeof payload === "number"

          ? payload

          : Number(
              payload?.currentTime
              ??
              payload
              ??
              0
            );


      if (
        Number.isFinite(value)
      ) {

        currentPlaybackTime =
          value;


        currentTime.textContent =
          formatClock(
            value
          );

      }

    }
  );


  /*
   * Keep our local playing state synchronized
   * when the user uses rrweb's own controller.
   */
  playerInstance.addEventListener(
    "ui-update-player-state",
    (event) => {

      const payload =
        event?.detail?.payload
        ??
        event?.payload
        ??
        event?.detail;


      if (
        typeof payload === "boolean"
      ) {

        isPlaying =
          payload;

      } else if (
        typeof payload === "string"
      ) {

        isPlaying =
          payload === "playing";

      } else if (
        payload &&
        typeof payload === "object"
      ) {

        if (
          typeof payload.isPlaying
          === "boolean"
        ) {

          isPlaying =
            payload.isPlaying;

        } else if (
          payload.state
        ) {

          isPlaying =
            payload.state
            === "playing";

        }

      }

    }
  );

}


// --------------------------------------------------
// UI EVENTS
// --------------------------------------------------

sessionSelect.addEventListener(
  "change",
  () => {

    replaySession(
      sessionSelect.value
    );

  }
);


refreshButton.addEventListener(
  "click",
  () => {

    loadSessions();

  }
);


// --------------------------------------------------
// START
// --------------------------------------------------

loadSessions();
