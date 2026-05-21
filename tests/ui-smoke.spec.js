import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.errors = errors;
});

test.afterEach(async ({ page }) => {
  expect(page.errors).toEqual([]);
});

test("dashboard loads live collector data", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "DMZ Collector Overview" })).toBeVisible();
  await expect(page.locator(".stat-label", { hasText: "Total Events" }).first()).toBeVisible();
  await expect(page.locator("#health-pill")).toContainText("status: ok");
  await expect(page.locator("#fwd-pill")).toContainText("fwd on");
});

test("events filters survive background refresh and JSON modal copies safely", async ({ page }) => {
  await page.goto("/");
  await page.locator('button[data-tab="events"]').click();
  await expect(page.getByRole("heading", { name: "Event Console" })).toBeVisible();

  const search = page.locator("#flt-search");
  await search.fill("gds");
  await page.waitForTimeout(5600);
  await expect(search).toHaveValue("gds");

  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.locator("#tab-events")).toContainText("gds_unauthorized_request");
  await page.locator("#tab-events tr", { hasText: "gds_unauthorized_request" }).locator(".show-json").click();
  await expect(page.locator("#json-modal")).toBeVisible();
  await expect(page.locator("#json-modal-body")).toContainText("gds_unauthorized_request");
  await page.getByRole("button", { name: "Copy JSON" }).click();
  await expect(page.getByRole("button", { name: /Copied|Copy failed/ })).toBeVisible();
});

test("stream controls render and pause/resume", async ({ page }) => {
  await page.goto("/");
  await page.locator('button[data-tab="events"]').click();
  await expect(page.locator("#stream-toggle")).toHaveText("Pause");
  await page.locator("#stream-toggle").click();
  await expect(page.locator("#stream-toggle")).toHaveText("Resume");
  await page.locator("#stream-toggle").click();
  await expect(page.locator("#stream-toggle")).toHaveText("Pause");
});

test("queue and HEC pages show merged forwarding counters", async ({ page }) => {
  await page.goto("/");
  await page.locator('button[data-tab="queue"]').click();
  await expect(page.getByRole("heading", { name: "Forwarding Queue" })).toBeVisible();
  await expect(page.locator("#tab-queue")).toContainText("HEC/syslog success");
  await expect(page.locator("#tab-queue")).toContainText("splunk status 503");

  await page.locator('button[data-tab="forwarding"]').click();
  await expect(page.getByRole("heading", { name: "SIEM Forwarding" })).toBeVisible();
  await expect(page.locator("#tab-forwarding")).toContainText("splunk status 503");

  await page.locator('button[data-tab="splunk"]').click();
  await expect(page.getByRole("heading", { name: "SIEM / Routing Reference" })).toBeVisible();
  await expect(page.locator("#tab-splunk")).toContainText("evt-critical-1");
});

test("all operator tabs render without crashing", async ({ page }) => {
  await page.goto("/");
  const tabs = [
    ["sources", "Source Registry"],
    ["queue", "Forwarding Queue"],
    ["forwarding", "SIEM Forwarding"],
    ["rules", "Rule Matrix"],
    ["splunk", "SIEM / Routing Reference"],
    ["settings", "Diagnostics"],
  ];
  for (const [tab, heading] of tabs) {
    await page.locator(`button[data-tab="${tab}"]`).click();
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
  }
});

test("responsive layout keeps primary controls visible", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 820 });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "DMZ Collector Overview" })).toBeVisible();
  await expect(page.locator("#health-pill")).toBeVisible();
  await page.locator('button[data-tab="events"]').click();
  await expect(page.locator("#flt-search")).toBeVisible();
});
