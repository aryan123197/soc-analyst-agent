import { Component, useState, type ReactNode } from "react";
import { Console } from "./Console";
import { LiveFeed } from "./LiveFeed";

class Boundary extends Component<{ children: ReactNode }, { err: Error | null }> {
  state = { err: null as Error | null };
  static getDerivedStateFromError(err: Error) {
    return { err };
  }
  render() {
    if (this.state.err) {
      return (
        <div className="error">
          <strong>The view crashed</strong>
          {this.state.err.message}
          <br />
          Reload the page. If it recurs, the response shape probably drifted from
          soc_agent/server.py.
        </div>
      );
    }
    return this.props.children;
  }
}

export function App() {
  const [tab, setTab] = useState<"console" | "live">("console");

  return (
    <div className="app">
      <header className="top">
        <div>
          <div className="eyebrow">SOC analyst agent · demo console</div>
          <h1>Untrusted input is screened before the model sees it</h1>
        </div>
        <div className="endpoints">
          <span>POST /ingest</span>
          <span>GET /corpus</span>
          <span>GET /live/stream</span>
        </div>
      </header>

      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "console"} onClick={() => setTab("console")}>
          CONSOLE
        </button>
        <button role="tab" aria-selected={tab === "live"} onClick={() => setTab("live")}>
          LIVE FEED
        </button>
      </div>

      {/* Both views stay mounted and are hidden with CSS rather than swapped:
          unmounting the console would throw away the run history mid-demo, and
          unmounting the feed would drop the event stream and every case with it. */}
      <Boundary>
        <div hidden={tab !== "console"}>
          <Console />
        </div>
        <div hidden={tab !== "live"}>
          <LiveFeed />
        </div>
      </Boundary>
    </div>
  );
}
