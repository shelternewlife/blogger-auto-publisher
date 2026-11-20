import { describe, expect, it } from "vitest";
import { validatePostInput } from "../src/index";

describe("validatePostInput", () => {
  it("accepts a complete direct-publication request", () => {
    expect(validatePostInput({
      blogId: "123456",
      title: "A useful article",
      content: "<h1>Hello</h1><p>Article body</p>",
      labels: ["SEO", "Guides"],
    })).toEqual({
      blogId: "123456",
      title: "A useful article",
      content: "<h1>Hello</h1><p>Article body</p>",
      labels: ["SEO", "Guides"],
    });
  });

  it("rejects a missing blog id", () => {
    expect(() => validatePostInput({ title: "Title", content: "<p>Body</p>" })).toThrow(/blogId is required/);
  });

  it("rejects empty content", () => {
    expect(() => validatePostInput({ blogId: "1", title: "Title", content: " " })).toThrow(/content is required/);
  });

  it("limits label count", () => {
    expect(() => validatePostInput({
      blogId: "1", title: "Title", content: "<p>Body</p>", labels: Array.from({ length: 21 }, (_, i) => String(i)),
    })).toThrow(/at most 20 labels/);
  });
});
