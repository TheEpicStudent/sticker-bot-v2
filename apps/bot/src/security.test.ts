import assert from "node:assert/strict";
import { test } from "node:test";

import {
  downloadSlackImage,
  validateImageMetadata,
  validateStickerInput,
  validDimensions,
} from "./security.ts";
import { slackEmojiRequest } from "./slack-emoji.ts";

const mockFetch = (
  fn: (
    input: string | URL | Request,
    init?: RequestInit,
  ) => Response | Promise<Response>,
) => fn as typeof fetch;

test("dimensions and names reject malicious or excessive inputs", () => {
  for (const n of [-1, 0, 17, Infinity, NaN, 1.5])
    assert.equal(validDimensions(n, 2), false);
  assert.equal(validDimensions(16, 16), true);
  for (const title of ["<@everyone>", "../name", "a".repeat(51), "old+name"])
    assert.throws(() => validateStickerInput(title, 2, 2));
  validateStickerInput("a-good_name", 2, 3);
  assert.throws(() =>
    validateImageMetadata({
      width: 100,
      height: 100,
      format: "gif",
      pages: 51,
    }),
  );
  assert.throws(() =>
    validateImageMetadata({ width: 10000, height: 10000, format: "png" }),
  );
});

test("private file downloads reject untrusted hosts before sending credentials", async () => {
  for (const url of [
    "http://files.slack.com/x",
    "https://files.slack.com.evil.test/x",
    "https://127.0.0.1/x",
    "https://user@files.slack.com/x",
  ]) {
    await assert.rejects(
      downloadSlackImage(
        url,
        "secret",
        mockFetch(() => {
          throw Error("must not fetch");
        }),
      ),
      /Untrusted/,
    );
  }
  const data = await downloadSlackImage(
    "https://files.slack.com/x",
    "secret",
    mockFetch((_url, init) => {
      assert.equal(init?.redirect, "error");
      assert.equal(
        new Headers(init?.headers).get("Authorization"),
        "Bearer secret",
      );
      return new Response("image");
    }),
  );
  assert.equal(data.toString(), "image");
});

test("download enforces streamed size and HTTP status", async () => {
  await assert.rejects(
    downloadSlackImage(
      "https://files.slack.com/x",
      "s",
      mockFetch(() => new Response("no", { status: 403 })),
    ),
  );
  await assert.rejects(
    downloadSlackImage(
      "https://files.slack.com/x",
      "s",
      mockFetch(() => new Response(new Uint8Array(10 * 1024 * 1024 + 1))),
    ),
    /10 MiB/,
  );
});

test("Slack emoji upload uses bearer auth and multipart file contract", async () => {
  const form = new FormData();
  form.set("name", "test");
  form.set("mode", "data");
  form.set("image", new Blob(["image"]), "image.png");
  await slackEmojiRequest(
    "xoxp-secret",
    "upload",
    { form },
    mockFetch((url, init) => {
      assert.equal(String(url), "https://slack.com/api/emoji.add");
      assert.equal(init?.redirect, "error");
      assert.equal(
        new Headers(init?.headers).get("Authorization"),
        "Bearer xoxp-secret",
      );
      assert.equal((init?.body as FormData).get("name"), "test");
      assert.equal((init?.body as FormData).get("mode"), "data");
      assert.ok((init?.body as FormData).get("image") instanceof Blob);
      assert.equal((init?.body as FormData).get("token"), "xoxp-secret");
      return Response.json({ ok: true });
    }),
  );
});

test("Slack emoji API fails closed on all errors and does not replay mutations", async () => {
  for (const response of [
    Response.json({ ok: false, error: "missing_scope" }),
    Response.json({ ok: false }, { status: 403 }),
    new Response("bad"),
    Response.json({ ok: false, error: "ratelimited" }),
  ]) {
    let calls = 0;
    await assert.rejects(
      slackEmojiRequest(
        "xoxp-secret",
        "remove",
        { name: "test" },
        mockFetch(() => {
          calls++;
          return response;
        }),
      ),
    );
    assert.equal(calls, 1);
  }
});

test("upload retries 429 with the same form and respects Retry-After", async () => {
  const form = new FormData();
  form.set("name", "same-name");
  form.set("image", new Blob(["image"]), "image.png");
  let calls = 0;
  const waits: number[] = [];
  await slackEmojiRequest(
    "xoxp-secret",
    "upload",
    { form },
    mockFetch((_url, init) => {
      assert.equal(init?.body, form);
      calls++;
      return calls < 3
        ? new Response(null, { status: 429, headers: { "Retry-After": "2" } })
        : Response.json({ ok: true });
    }),
    async (ms) => {
      waits.push(ms);
    },
  );
  assert.equal(calls, 3);
  assert.deepEqual(waits, [2250, 2250]);
});

test("upload retries are bounded and use exponential fallback", async () => {
  let calls = 0;
  const waits: number[] = [];
  await assert.rejects(
    slackEmojiRequest(
      "xoxp-secret",
      "upload",
      { form: new FormData() },
      mockFetch(() => {
        calls++;
        return new Response(null, { status: 429 });
      }),
      async (ms) => {
        waits.push(ms);
      },
    ),
    /ratelimited/,
  );
  assert.equal(calls, 5);
  assert.deepEqual(waits, [1250, 2250, 4250, 8250]);
});

test("upload does not replay ambiguous errors or shorten long Retry-After", async () => {
  for (const status of [400, 401, 403, 409, 500, 502, 503, 504, 429]) {
    let calls = 0;
    await assert.rejects(
      slackEmojiRequest(
        "xoxp-secret",
        "upload",
        { form: new FormData() },
        mockFetch(() => {
          calls++;
          return new Response(null, {
            status,
            headers: { "Retry-After": "120" },
          });
        }),
        async () => {
          assert.fail("must not wait");
        },
      ),
    );
    assert.equal(calls, 1);
  }
  let calls = 0;
  await assert.rejects(
    slackEmojiRequest(
      "xoxp-secret",
      "upload",
      { form: new FormData() },
      mockFetch(() => {
        calls++;
        throw new Error("timeout");
      }),
    ),
  );
  assert.equal(calls, 1);
});
