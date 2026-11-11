declare module 'vitest' {
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export function beforeAll(fn: () => void | Promise<void>): void;
  export function afterAll(fn: () => void | Promise<void>): void;
  export interface Assertion<T = any> {
    not: Assertion<T>;
    toBe(expected: T): void;
    toEqual(expected: unknown): void;
    toHaveLength(length: number): void;
    toMatch(pattern: RegExp | string): void;
    toContain(substring: unknown): void;
    toBeDefined(): void;
    toBeUndefined(): void;
    toBeNull(): void;
    toBeGreaterThan(n: number): void;
    toBeGreaterThanOrEqual(n: number): void;
    toBeLessThan(n: number): void;
    toBeCloseTo(n: number, precision?: number): void;
    toThrow(error?: RegExp | string): void;
  }
  export function expect<T>(actual: T, message?: string): Assertion<T>;
}
