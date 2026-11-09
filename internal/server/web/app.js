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

function concatBytes(...arrays) {
  const result = new Uint8Array(arrays.reduce((size, array) => size + array.length, 0));
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

function uint32(value) {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ]);
}

function sshString(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return concatBytes(uint32(bytes.length), bytes);
}

function toBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function pem(label, bytes) {
  const base64 = toBase64(bytes);
  const lines = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function ed25519PrivateKeyOpenSSH(seed, publicKey) {
  const check = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(check.buffer).getUint32(0, false);
  const privateBlock = concatBytes(
    uint32(checkInt),
    uint32(checkInt),
    sshString("ssh-ed25519"),
    sshString(publicKey),
    sshString(concatBytes(seed, publicKey)),
    sshString("JIT ephemeral key")
  );
  const paddingLength = (8 - (privateBlock.length % 8)) % 8;
  const padding = Uint8Array.from({ length: paddingLength }, (_, index) => index + 1);
  const paddedPrivateBlock = concatBytes(privateBlock, padding);
  const publicBlob = concatBytes(sshString("ssh-ed25519"), sshString(publicKey));
  const magic = new TextEncoder().encode("openssh-key-v1\0");
  const opensshPrivateKey = concatBytes(
    magic,
    sshString("none"),
    sshString("none"),
    sshString(new Uint8Array()),
    uint32(1),
    sshString(publicBlob),
    sshString(paddedPrivateBlock)
  );
  return pem("OPENSSH PRIVATE KEY", opensshPrivateKey);
}

async function createEphemeralKeyPair() {
  if (!window.isSecureContext || !crypto.subtle) {
    throw new Error("Open this page over HTTPS in a browser with WebCrypto support to create an SSH key.");
  }
  let keyPair;
  try {
    keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  } catch {
    throw new Error("This browser does not support creating Ed25519 SSH keys. Try a current version of Chrome, Firefox, or Safari.");
  }
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const pkcs8Prefix = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
  if (pkcs8.length !== pkcs8Prefix.length + 32 ||
      !pkcs8Prefix.every((byte, index) => pkcs8[index] === byte)) {
    throw new Error("Could not encode the browser-generated Ed25519 key for OpenSSH.");
  }
  const seed = pkcs8.slice(pkcs8Prefix.length);
  const publicBlob = concatBytes(sshString("ssh-ed25519"), sshString(publicKey));
  return {
    publicKey: `ssh-ed25519 ${toBase64(publicBlob)} web-access`,
    privateKey: ed25519PrivateKeyOpenSSH(seed, publicKey)
  };
}

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

  submitButton.disabled = true;
  submitButton.textContent = "Generating key and requesting certificate…";
  try {
    const keyPair = await createEphemeralKeyPair();
    const certificate = await requestCertificate(username, username, duration, keyPair.publicKey);
    const credentialId = Array.from(crypto.getRandomValues(new Uint8Array(8)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const keyFilename = `jit-${credentialId}`;
    const certificateFilename = `${keyFilename}-cert.pub`;
    const keyPath = `"$HOME/.ssh/jit/${keyFilename}"`;
    const certificatePath = `"$HOME/.ssh/jit/${certificateFilename}"`;
    const commands = [
      `mkdir -p "$HOME/.ssh/jit" && chmod 700 "$HOME/.ssh/jit"`,
      `mv -- "$HOME/Downloads/${keyFilename}" ${keyPath}`,
      `mv -- "$HOME/Downloads/${certificateFilename}" ${certificatePath}`,
      `chmod 600 ${keyPath} ${certificatePath}`,
      `ssh -i ${keyPath} -o "CertificateFile=$HOME/.ssh/jit/${certificateFilename}" ${quoteShell(`${username}@${targetHost}`)}`
    ];
    downloadFile(keyFilename, keyPair.privateKey, "application/octet-stream");
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
