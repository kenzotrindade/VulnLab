import { useState, useEffect } from "react";

interface ScanResult {
  Header?: any;
  Files?: any;
  Cookies?: any;
  InjectionsSQL?: any;
  InjectionXSS?: any;
}

interface VulnInfo {
  desc: string;
  impact: string;
  recom: string;
}

const vulnDB: Record<string, VulnInfo> = {
  HEADER_INTEGRITY: {
    desc: "Analysis of HTTP security headers.",
    impact: "High",
    recom: "Add missing security headers.",
  },
  SENSITIVE_FILES: {
    desc: "Critical files accessible to the public.",
    impact: "Fatal",
    recom: "Restrict access via server.",
  },
  COOKIE_SECURITY: {
    desc: "Analysis of HttpOnly and Secure attributes.",
    impact: "Medium",
    recom: "Configure security flags.",
  },
  SQL_INJECTION: {
    desc: "Detection of SQL vulnerabilities.",
    impact: "Critical",
    recom: "Use prepared statements.",
  },
  XSS_INJECTION: {
    desc: "Analysis of reflected scripts.",
    impact: "Critical",
    recom: "Clean inputs and use CSP.",
  },
};

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [score, setScore] = useState(100);
  const [selectedModule, setSelectedModule] = useState<{
    id: string;
    tech: string;
  } | null>(null);

  function getModuleStatus(id: string, info: any) {
    if (info && info.error === "ERROR") {
      return {
        text: "ENGINE ERROR",
        class: "tag-warning",
        tech: "Technical issue detected.",
        penalty: 0,
      };
    }

    if (id === "HEADER_INTEGRITY" && info && info.data) {
      let missingList = "";
      let missingCount = 0;
      for (let headerName in info.data) {
        if (info.data[headerName] === "Missing") {
          missingList = missingList + "• " + headerName + "\n";
          missingCount = missingCount + 1;
        }
      }
      if (missingCount > 0) {
        return {
          text: "VULNERABLE",
          class: "tag-danger",
          tech: "Missing:\n" + missingList,
          penalty: missingCount * 4,
        };
      }
    }

    if (id === "SENSITIVE_FILES" && info) {
      let foundList = "";
      let foundCount = 0;
      for (let fileName in info) {
        if (info[fileName] === true) {
          foundList = foundList + "• " + fileName + "\n";
          foundCount = foundCount + 1;
        }
      }
      if (foundCount > 0) {
        return {
          text: "VULNERABLE",
          class: "tag-danger",
          tech: "Found:\n" + foundList,
          penalty: 25,
        };
      }
    }

    if (id === "SQL_INJECTION" || id === "XSS_INJECTION") {
      if (info && info.vuln === true) {
        return {
          text: "VULNERABLE",
          class: "tag-danger",
          tech: "Vulnerability signature detected.",
          penalty: 35,
        };
      }
    }

    if (id === "COOKIE_SECURITY" && info && info.data) {
      let cookieIssues = "";
      let hasIssues = false;
      for (let cookieName in info.data) {
        let flags = info.data[cookieName];
        let details = "";
        if (flags.HttpOnly === "Missing") {
          details = details + "HttpOnly ";
        }
        if (flags.Secure === "Missing") {
          details = details + "Secure";
        }
        if (details !== "") {
          cookieIssues =
            cookieIssues + "[" + cookieName + "] missing: " + details + "\n";
          hasIssues = true;
        }
      }
      if (hasIssues === true) {
        return {
          text: "UNSECURE",
          class: "tag-danger",
          tech: cookieIssues,
          penalty: 10,
        };
      }
    }

    return {
      text: "SECURE",
      class: "tag-success",
      tech: "No problems detected.",
      penalty: 0,
    };
  }

  useEffect(() => {
    if (results !== null) {
      let totalPenalty = 0;
      const dataMapping: any = {
        HEADER_INTEGRITY: results.Header,
        SENSITIVE_FILES: results.Files,
        COOKIE_SECURITY: results.Cookies,
        SQL_INJECTION: results.InjectionsSQL,
        XSS_INJECTION: results.InjectionXSS,
      };

      for (let key in vulnDB) {
        let status = getModuleStatus(key, dataMapping[key]);
        totalPenalty = totalPenalty + status.penalty;
      }

      let newScore = 100 - totalPenalty;
      if (newScore < 0) {
        setScore(0);
      } else {
        setScore(newScore);
      }
    }
  }, [results]);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResults(null);
    setScore(100);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/scan?url=" + encodeURIComponent(url),
      );
      const res = await response.json();
      if (res.success === true) {
        setResults(res.data);
      }
    } catch (err) {
      alert("ERROR: Server unreachable");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-container">
      <header className="main-header">
        <div className="logo">
          Vulns<span>Scan</span>
        </div>
        <div className="badge-status">Engine ready</div>
      </header>

      <section className="search-area">
        <h1>Audit your application security</h1>
        <p>Enter a URL to identify critical vulnerabilities.</p>
        <form onSubmit={handleScan} className="search-box">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://google.com"
            required
          />
          <button type="submit">Start analysis</button>
        </form>
      </section>

      {loading === true && <div className="spinner" />}

      {results !== null && (
        <div id="dashboard">
          <div className="summary-grid">
            <div className="summary-card">
              <span className="label">Trust Index</span>
              <div
                className="value"
                style={{
                  color:
                    score < 50
                      ? "var(--danger)"
                      : score < 85
                        ? "var(--warning)"
                        : "var(--success)",
                }}
              >
                {score}%
              </div>
            </div>
          </div>

          <div className="results-grid">
            {Object.keys(vulnDB).map((key) => {
              const dataMapping: any = {
                HEADER_INTEGRITY: results.Header,
                SENSITIVE_FILES: results.Files,
                COOKIE_SECURITY: results.Cookies,
                SQL_INJECTION: results.InjectionsSQL,
                XSS_INJECTION: results.InjectionXSS,
              };
              const status = getModuleStatus(key, dataMapping[key]);
              return (
                <div
                  key={key}
                  className="card"
                  onClick={() =>
                    setSelectedModule({ id: key, tech: status.tech })
                  }
                >
                  <h4>{key.replace("_", " ")}</h4>
                  <span className={"tag " + status.class}>{status.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {selectedModule !== null && (
        <div className="modal-overlay" onClick={() => setSelectedModule(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <button
              className="close-btn"
              onClick={() => setSelectedModule(null)}
            >
              &times;
            </button>
            <h2>{selectedModule.id.replace("_", " ")}</h2>
            <hr />
            <p>
              <strong>Description:</strong> {vulnDB[selectedModule.id].desc}
            </p>
            <p>
              <strong>Impact:</strong> {vulnDB[selectedModule.id].impact}
            </p>
            <h4>Technical Details & Remediation</h4>
            <pre>{selectedModule.tech}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
