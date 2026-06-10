import { describe, expect, it } from "vitest";
import { mapPublicPostEvent } from "./events";

describe("mapPublicPostEvent", () => {
  it("projects the snake_case wire event to a camelCase delivery", () => {
    const d = mapPublicPostEvent({
      verified_actor_url: "https://m.example/users/a",
      activity_json: '{"type":"Note","content":"hi"}',
    });
    expect(d.verifiedActorUrl).toBe("https://m.example/users/a");
    expect(d.activityJson).toBe('{"type":"Note","content":"hi"}');
  });

  it("carries the activity body through verbatim (renderer owns parsing)", () => {
    const raw = '{"type":"Create","object":{"type":"Note","content":"<p>x</p>"}}';
    expect(mapPublicPostEvent({ verified_actor_url: "u", activity_json: raw }).activityJson).toBe(raw);
  });
});
