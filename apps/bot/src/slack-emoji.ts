type EmojiOperation = "upload" | "remove";

export async function slackEmojiRequest(
  token: string,
  operation: EmojiOperation,
  options: {
    name?: string;
    form?: FormData;
    signal?: AbortSignal;
  },
  fetcher: typeof fetch = fetch,
  wait: (ms: number) => Promise<void> = (ms) =>
    new Promise((resolve) => setTimeout(resolve, ms)),
): Promise<void> {
  const form =
    options.form ??
    (() => {
      const value = new FormData();
      value.append("name", options.name!);
      return value;
    })();

  form.append("token", token);

  for (let attempt = 0; attempt < 5; attempt++) {
    let response: Response;
    try {
      response = await fetcher(
        `https://slack.com/api/emoji.${operation === "upload" ? "add" : "remove"}`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: form,
          redirect: "error",
          signal: AbortSignal.any([
            AbortSignal.timeout(30_000),
            ...(options.signal ? [options.signal] : []),
          ]),
        },
      );
    } catch {
      throw new Error(
        "Slack emoji request failed; check the user token and API before retrying",
      );
    }

    if (response.status === 429 && attempt < 4) {
      const header = response.headers.get("Retry-After");
      const seconds = header === null ? NaN : Number(header);
      const date = header === null ? NaN : Date.parse(header);
      const delay =
        Number.isFinite(seconds) && seconds >= 0
          ? seconds * 1000
          : Number.isFinite(date)
            ? Math.max(0, date - Date.now())
            : 1000 * 2 ** attempt;
      if (delay <= 60_000) {
        await response.body?.cancel();
        if (options.signal) options.signal.throwIfAborted();
        await wait(delay + 250);
        continue;
      }
    }

    const data: unknown = await response.json().catch(() => null);
    if (
      response.ok &&
      data &&
      typeof data === "object" &&
      "ok" in data &&
      data.ok === true
    )
      return;

    let code = "unknown_error";
    if (response.status === 429) code = "ratelimited";
    if (data && typeof data === "object" && "error" in data) {
      if (typeof data.error === "string") code = data.error;
    }
    const error = new Error(`Slack emoji API returned ${code}`);
    Object.assign(error, { data: { error: code } });
    throw error;
  }
}
