"use strict";

const form = document.querySelector("#access-form");
const hostInput = document.querySelector("#issuer-host");
const portInput = document.querySelector("#issuer-port");
const schemeInput = document.querySelector("#issuer-scheme");
const result = document.querySelector("#command-result");
const commandOutput = document.querySelector("#cli-command");

if (hostInput && portInput && schemeInput) {
  const isSecure = window.location.protocol === "https:";
  hostInput.value = window.location.hostname;
  portInput.value = window.location.port || (isSecure ? "443" : "8080");
  schemeInput.value = isSecure ? "https" : "http";
}

function quoteShell(value) {
  return "'" + value.replaceAll("'", "'\"'\"'") + "'";
}

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;

  const username = document.querySelector("#target-user").value.trim();
  const targetHost = document.querySelector("#target-host").value.trim();
  const duration = document.querySelector("#duration").value;
  const issuerHost = hostInput.value.trim();
  const port = Number(portInput.value);
  const scheme = schemeInput.value;

  if (!/^[a-zA-Z0-9._-]+$/.test(username) || username.startsWith("-")) {
    document.querySelector("#target-user").setCustomValidity("Use a valid SSH account name.");
    document.querySelector("#target-user").reportValidity();
    document.querySelector("#target-user").setCustomValidity("");
    return;
  }
  if (!/^[a-zA-Z0-9.:[\]-]+$/.test(targetHost) || targetHost.startsWith("-")) {
    document.querySelector("#target-host").setCustomValidity("Use a hostname or IP address, without spaces.");
    document.querySelector("#target-host").reportValidity();
    document.querySelector("#target-host").setCustomValidity("");
    return;
  }
  if (!/^[a-zA-Z0-9.:[\]-]+$/.test(issuerHost) || issuerHost.startsWith("-") || !Number.isInteger(port) || port < 1 || port > 65535) {
    hostInput.setCustomValidity("Enter a valid issuer hostname or IP and port.");
    hostInput.reportValidity();
    hostInput.setCustomValidity("");
    return;
  }

  const urlHost = issuerHost.includes(":") && !issuerHost.startsWith("[")
    ? `[${issuerHost}]`
    : issuerHost;
  let serverURL;
  try {
    serverURL = new URL(`${scheme}://${urlHost}:${port}`).origin;
  } catch {
    hostInput.setCustomValidity("Enter a valid issuer hostname or IP.");
    hostInput.reportValidity();
    hostInput.setCustomValidity("");
    return;
  }
  const parts = [
    "jit-cli", "access", "--user", username,
    "--host", targetHost, "--duration", duration,
    "--server", serverURL
  ];
  commandOutput.textContent = parts.map(quoteShell).join(" \\\n  ");
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "nearest" });
});

document.querySelector("#copy-command")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  try {
    await navigator.clipboard.writeText(commandOutput.textContent);
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = "Copy command"; }, 1800);
  } catch {
    button.textContent = "Select and copy the command";
  }
});
