"use strict";

const form = document.querySelector("#access-form");
const result = document.querySelector("#command-result");
const commandOutput = document.querySelector("#cli-command");
const errorOutput = document.querySelector("#request-error");
const submitButton = document.querySelector("#generate-command");
const starButton = document.querySelector("#star-button");
const starCount = document.querySelector("#star-count");
const starStatus = document.querySelector("#star-status");
const contactForm = document.querySelector("#contact-form");

function downloadFile(filename, contents, type) {
  const blobURL = URL.createObjectURL(new Blob([contents], { type }));
  const link = document.createElement("a");
  link.href = blobURL;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(blobURL), 1000);
}

function quoteShell(value) {
  return "'" + value.replaceAll("'", "'\"'\"'") + "'";
}

async function requestCertificate(identity, targetUser, duration, publicKey) {
  const response = await fetch("/api/v1/request-access", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      identity,
      target_user: targetUser,
      duration_minutes: Number.parseInt(duration, 10),
      public_key: publicKey
    })
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `Certificate request failed (HTTP ${response.status}).`);
  }
  if (typeof body.certificate !== "string" || !body.certificate.trim()) {
    throw new Error("The issuer returned an empty certificate.");
  }
  return body.certificate.trim() + "\n";
}

async function updateStars(method = "GET") {
  const response = await fetch("/api/v1/stars", { method });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !Number.isSafeInteger(body.count) || body.count < 0) {
    throw new Error(body.error || `Could not load stars (HTTP ${response.status}).`);
  }
  starCount.textContent = body.count.toLocaleString();
  return body.count;
}

if (starButton && starCount) {
  updateStars()
    .then(() => { starButton.disabled = false; })
    .catch((error) => {
      starCount.textContent = "Unavailable";
      starStatus.textContent = error instanceof Error ? error.message : "Could not load stars.";
    });

  starButton.addEventListener("click", async () => {
    starButton.disabled = true;
    try {
      await updateStars("POST");
      starStatus.textContent = "";
    } catch (error) {
      starStatus.textContent = error instanceof Error ? error.message : "Could not add a star.";
    } finally {
      starButton.disabled = false;
    }
  });
}

contactForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!contactForm.reportValidity()) return;

  const name = document.querySelector("#contact-name").value.trim();
  const email = document.querySelector("#contact-email").value.trim();
  const message = document.querySelector("#contact-message").value.trim();
  const subject = "Ephemeral SSH contact";
  const body = `Name: ${name}\nEmail: ${email}\n\n${message}`;
  const mailto = `mailto:reachtoamit7@gmail.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.location.href = mailto;
  document.querySelector("#contact-status").textContent = "Your email app should open with your message addressed to reachtoamit7@gmail.com.";
});

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  errorOutput.hidden = true;

  const username = document.querySelector("#target-user").value.trim();
  const targetHost = document.querySelector("#target-host").value.trim();
  const publicKey = document.querySelector("#public-key").value.trim();
  const privateKeyPath = document.querySelector("#private-key-path").value.trim();
  const duration = document.querySelector("#duration").value;
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
  if (!/^[a-zA-Z0-9._/+~-]+$/.test(privateKeyPath) || privateKeyPath.startsWith("-")) {
    document.querySelector("#private-key-path").setCustomValidity("Use a file path without spaces or shell characters.");
    document.querySelector("#private-key-path").reportValidity();
    document.querySelector("#private-key-path").setCustomValidity("");
    return;
  }
  if (!/^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))\s+\S+/.test(publicKey)) {
    document.querySelector("#public-key").setCustomValidity("Paste a valid OpenSSH public key, such as the contents of id_ed25519.pub.");
    document.querySelector("#public-key").reportValidity();
    document.querySelector("#public-key").setCustomValidity("");
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "Requesting certificate…";
  try {
    const certificate = await requestCertificate(username, username, duration, publicKey);
    const credentialId = Array.from(crypto.getRandomValues(new Uint8Array(8)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const certificateFilename = `jit-${credentialId}-cert.pub`;
    const certificatePath = `"$HOME/.ssh/jit/${certificateFilename}"`;
    const privateKeyArgument = privateKeyPath.startsWith("~/")
      ? `"$HOME/${privateKeyPath.slice(2)}"`
      : quoteShell(privateKeyPath);
    const commands = [
      `mkdir -p "$HOME/.ssh/jit" && chmod 700 "$HOME/.ssh/jit"`,
      `mv -- "$HOME/Downloads/${certificateFilename}" ${certificatePath}`,
      `chmod 600 ${certificatePath}`,
      `ssh -i ${privateKeyArgument} -o "CertificateFile=$HOME/.ssh/jit/${certificateFilename}" ${quoteShell(`${username}@${targetHost}`)}`
    ];
    downloadFile(certificateFilename, certificate, "application/vnd.openssh.cert");
    commandOutput.textContent = commands.join(" && \\\n  ");
    result.hidden = false;
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    errorOutput.textContent = error instanceof Error ? error.message : "Certificate request failed.";
    errorOutput.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = 'Request certificate &amp; prepare SSH command <span aria-hidden="true">→</span>';
  }
});

document.querySelector("#copy-command")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  try {
    await navigator.clipboard.writeText(commandOutput.textContent);
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = "Copy SSH command"; }, 1800);
  } catch {
    button.textContent = "Select and copy the command";
  }
});
