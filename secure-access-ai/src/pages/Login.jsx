
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginToWarpgate, getWarpgateInfo } from "../api/warpgate";
import { logSecureAccessEvent } from "../api/audit";

import {
  Shield,
  Play,
  KeyRound,
  Sparkles,
  Eye,
  EyeOff,
} from "lucide-react";

import "../styles/Login.css";

function Login() {
  const [showPassword, setShowPassword] = useState(false);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const navigate = useNavigate();

  const handleLogin = async (event) => {
  event.preventDefault();

  if (!username || !password) {
    setError("Please enter your username and password.");
    return;
  }

  try {
    setError("");

    const result = await loginToWarpgate(username, password);

    if (!result.success) {
      if (result.state === "OtpNeeded") {
        setError("OTP authentication is required.");
      } else if (result.state === "SsoNeeded") {
        setError("SSO authentication is required.");
      } else if (result.state === "UserLocked") {
        setError("This account is locked.");
      } else if (result.state === "IpBlocked") {
        setError("Login blocked from this IP address.");
      } else {
        setError("Invalid username or password.");
      }

      return;
    }

    const info = await getWarpgateInfo();

    console.log("Logged in user:", info);

    if (info.username) {
      void logSecureAccessEvent("auth", "login.succeeded");
      navigate("/admin");
    } else {
      setError("Login succeeded, but the session could not be verified.");
    }
  } catch (error) {
    console.error("Login error:", error);
    setError("Unable to reach the SecureAccess sign-in service.");
  }
};

  return (
    <main className="login-page">
      {/* LEFT PANEL */}

      <section className="login-left">
        <div className="left-brand">
          <Shield size={28} strokeWidth={2} />
          <span>SecureAccess</span>
        </div>

        <div className="left-content">
          <h1>
            Secure access.
            <br />
            Complete visibility.
          </h1>

          <p className="left-description">
            Secure infrastructure access, automatic session recording,
            role-based access control, and AI-powered security insights.
          </p>

          <div className="feature-list">
            <div className="feature-item">
              <div className="feature-icon">
                <Shield size={23} />
              </div>

              <span>Secure Infrastructure Access</span>
            </div>

            <div className="feature-item">
              <div className="feature-icon">
                <Play size={23} />
              </div>

              <span>Automatic Session Recording</span>
            </div>

            <div className="feature-item">
              <div className="feature-icon">
                <KeyRound size={23} />
              </div>

              <span>Role-Based Access Control</span>
            </div>

            <div className="feature-item">
              <div className="feature-icon">
                <Sparkles size={23} />
              </div>

              <span>AI-Powered Insights</span>
            </div>
          </div>
        </div>
      </section>

      {/* RIGHT PANEL */}

      <section className="login-right">
        <div className="login-container">
          <div className="right-brand">
            <Shield size={30} strokeWidth={2} />
            <span>SecureAccess</span>
          </div>

          <div className="welcome-section">
            <h2>Welcome back</h2>

            <p>Sign in to continue to SecureAccess</p>
          </div>

          <form className="login-form" onSubmit={handleLogin}>
            {/* USERNAME */}

            <input
              type="text"
              placeholder="Username or Email"
              className="form-input"
              value={username}
              onChange={(event) => {
                setUsername(event.target.value);
                setError("");
              }}
            />

            {/* PASSWORD */}

            <div className="password-container">
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Password"
                className="form-input"
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                  setError("");
                }}
              />

              <button
                type="button"
                className="password-button"
                onClick={() => setShowPassword((current) => !current)}
                aria-label="Show or hide password"
              >
                {showPassword ? (
                  <EyeOff size={20} />
                ) : (
                  <Eye size={20} />
                )}
              </button>
            </div>

            {/* LOGIN OPTIONS */}

            <div className="login-options">
              <label className="remember-me">
                <input type="checkbox" />
                <span>Remember me</span>
              </label>

              <button type="button" className="forgot-password">
                Forgot password?
              </button>
            </div>

            {/* ERROR MESSAGE */}

            {error && <p className="login-error">{error}</p>}

            {/* SIGN IN */}

            <button type="submit" className="sign-in-button">
              Sign In
            </button>

            {/* DIVIDER */}

            <div className="divider">
              <span />
              <p>or</p>
              <span />
            </div>

            {/* SSO */}

            <button type="button" className="sso-button">
              Continue with SSO
            </button>
          </form>
        </div>

        <p className="login-footer">
          Protected access • All sessions are audited
        </p>
      </section>
    </main>
  );
}

export default Login;