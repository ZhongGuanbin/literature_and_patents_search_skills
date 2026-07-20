import fs from "node:fs/promises";

const DESCRIPTOR_SCHEMA = "laps_runtime_credential_broker_descriptor_v1";
const REQUEST_SCHEMA = "laps_runtime_credential_broker_request_v1";

function result(status, extra = {}) {
  return { status, ...extra };
}

function cssString(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/[\r\n\f]/g, " ");
}

function selectorCandidates(field) {
  if (!field || typeof field !== "object") return [];
  const tag = String(field.tag || "input").toLowerCase();
  const candidates = [];
  if (field.id) candidates.push(`${tag}[id="${cssString(field.id)}"]`);
  if (field.name) candidates.push(`${tag}[name="${cssString(field.name)}"]`);
  if (field.autocomplete) {
    candidates.push(
      `${tag}[autocomplete="${cssString(field.autocomplete)}"]`,
    );
  }
  if (field.type) candidates.push(`${tag}[type="${cssString(field.type)}"]`);
  return [...new Set(candidates)];
}

async function uniqueVisibleLocator(tab, field) {
  for (const selector of selectorCandidates(field)) {
    const locator = tab.playwright.locator(selector);
    if ((await locator.count()) !== 1) continue;
    if (
      typeof locator.isVisible === "function" &&
      !(await locator.isVisible())
    ) {
      continue;
    }
    if (
      typeof locator.isEnabled === "function" &&
      !(await locator.isEnabled())
    ) {
      continue;
    }
    return { locator, selector };
  }
  return null;
}

async function inspectCredentialForm(tab) {
  return tab.playwright.evaluate(() => {
    const visible = (element) => {
      const style = globalThis.getComputedStyle
        ? globalThis.getComputedStyle(element)
        : null;
      const rect = element.getBoundingClientRect();
      return Boolean(
        !element.disabled &&
          (!style ||
            (style.display !== "none" && style.visibility !== "hidden")) &&
          rect.width > 0 &&
          rect.height > 0,
      );
    };
    const describe = (element) => {
      if (!element) return null;
      const tag = String(element.tagName || "input").toLowerCase();
      return {
            tag,
            type: element.getAttribute("type") || (tag === "button" ? "submit" : "text"),
            id: element.getAttribute("id") || "",
            name: element.getAttribute("name") || "",
            autocomplete: element.getAttribute("autocomplete") || "",
          };
    };
    const inputs = Array.from(document.querySelectorAll("input")).filter(
      visible,
    );
    const password = inputs.find(
      (element) =>
        String(element.getAttribute("type") || "").toLowerCase() ===
        "password",
    );
    const account = inputs.find((element) => {
      if (element === password) return false;
      const type = String(element.getAttribute("type") || "text").toLowerCase();
      const autocomplete = String(
        element.getAttribute("autocomplete") || "",
      ).toLowerCase();
      const identity = [
        element.getAttribute("id"),
        element.getAttribute("name"),
        element.getAttribute("aria-label"),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return (
        ["text", "email", "tel"].includes(type) &&
        (autocomplete === "username" ||
          autocomplete === "email" ||
          /(user|account|login|email|phone|mobile)/.test(identity))
      );
    });
    const submit = Array.from(
      document.querySelectorAll(
        'button[type="submit"], input[type="submit"], button:not([type])',
      ),
    ).find(visible);
    return {
      account: describe(account),
      password: describe(password),
      submit: describe(submit),
    };
  });
}

async function loadDescriptor(path) {
  const text = await fs.readFile(path, "utf8");
  const descriptor = JSON.parse(text);
  if (!descriptor || descriptor.schema !== DESCRIPTOR_SCHEMA) {
    throw new Error("credential_descriptor_invalid");
  }
  const endpoint = new URL(String(descriptor.endpoint || ""));
  if (
    endpoint.protocol !== "http:" ||
    endpoint.hostname !== "127.0.0.1" ||
    endpoint.pathname !== "/claim" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash
  ) {
    throw new Error("credential_descriptor_invalid");
  }
  return descriptor;
}

function contractMatches(descriptor, options) {
  return (
    String(descriptor.event_id || "") === String(options.eventId || "") &&
    String(descriptor.source || "") === String(options.source || "") &&
    String(descriptor.auth_state_scope || "") ===
      String(options.authStateScope || "") &&
    String(descriptor.institution_identity_digest || "") ===
      String(options.institutionIdentityDigest || "")
  );
}

async function claimRuntimeCredentials(descriptor, options, currentUrl) {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    Math.max(1000, Math.min(15000, Number(options.timeoutMs || 5000))),
  );
  try {
    const response = await fetch(descriptor.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      signal: controller.signal,
      body: JSON.stringify({
        schema: REQUEST_SCHEMA,
        capability: descriptor.capability,
        event_id: options.eventId,
        source: options.source,
        auth_state_scope: options.authStateScope,
        institution_identity_digest: options.institutionIdentityDigest,
        current_url: currentUrl,
        account_form_present: true,
        password_form_present: true,
      }),
    });
    const body = await response.json();
    return { ok: response.ok, body };
  } finally {
    clearTimeout(timeout);
  }
}

export async function fillRuntimeCredentials(options) {
  const tab = options?.tab;
  if (!tab?.playwright || typeof tab.url !== "function") {
    return result("credential_config_unavailable");
  }
  let account = null;
  let password = null;
  try {
    const descriptor = await loadDescriptor(options.descriptorPath);
    if (Number(descriptor.expires_at_epoch_seconds || 0) <= Date.now() / 1000) {
      return result("credential_broker_expired");
    }
    if (!contractMatches(descriptor, options)) {
      return result("credential_event_mismatch");
    }
    const currentUrl = String(await tab.url());
    const form = await inspectCredentialForm(tab);
    const accountTarget = await uniqueVisibleLocator(tab, form.account);
    const passwordTarget = await uniqueVisibleLocator(tab, form.password);
    if (!accountTarget || !passwordTarget) {
      return result("credential_form_not_found");
    }
    const claimed = await claimRuntimeCredentials(
      descriptor,
      options,
      currentUrl,
    );
    if (!claimed.ok) {
      return result(String(claimed.body?.status || "credential_broker_refused"));
    }
    account = claimed.body?.account;
    password = claimed.body?.password;
    if (typeof account !== "string" || typeof password !== "string") {
      return result("credential_config_unavailable");
    }
    await accountTarget.locator.fill(account);
    await passwordTarget.locator.fill(password);
    account = null;
    password = null;

    const submitTarget = await uniqueVisibleLocator(tab, form.submit);
    if (submitTarget) {
      await submitTarget.locator.click();
      return result("runtime_credentials_submitted", {
        filled: true,
        submitted: true,
      });
    }
    if (typeof passwordTarget.locator.press === "function") {
      await passwordTarget.locator.press("Enter");
      return result("runtime_credentials_submitted", {
        filled: true,
        submitted: true,
      });
    }
    return result("runtime_credentials_filled", {
      filled: true,
      submitted: false,
    });
  } catch (error) {
    const reason = String(error?.message || "");
    if (reason === "credential_descriptor_invalid") {
      return result(reason);
    }
    if (error?.name === "AbortError") {
      return result("credential_broker_expired");
    }
    return result("credential_fill_failed", {
      error_type: String(error?.name || "Error"),
    });
  } finally {
    account = null;
    password = null;
  }
}
