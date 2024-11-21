import { initEnvManager, transformEnv, validateEnv } from "../src/env";

// Define the environment variable interface
interface AppEnv {
	KEY1: string;
	KEY2: number;
}

describe("Environment Manager", () => {
	describe("validateEnv", () => {
		it("should throw an error if a required environment variable is missing", () => {
			const env = { KEY1: "value1" } as NodeJS.ProcessEnv;
			const requiredKeys = ["KEY1", "KEY2"] as (keyof AppEnv)[];

			expect(() => validateEnv(env, requiredKeys)).toThrow(
				"Missing required environment variable: KEY2",
			);
		});

		it("should not throw an error if all required environment variables are present", () => {
			const env = { KEY1: "value1", KEY2: "value2" } as NodeJS.ProcessEnv;
			const requiredKeys = ["KEY1", "KEY2"] as (keyof AppEnv)[];

			expect(() => validateEnv(env, requiredKeys)).not.toThrow();
		});
	});

	describe("transformEnv", () => {
		it("should transform environment variables based on the provided transformations", () => {
			const env = { KEY1: "value1", KEY2: "123" } as NodeJS.ProcessEnv;
			const transformations = {
				KEY1: (value: string) => value.toUpperCase(),
				KEY2: (value: string) => Number.parseInt(value, 10),
			};

			const result = transformEnv<Record<string, unknown>>(
				env,
				transformations,
			);

			expect(result).toEqual({ KEY1: "VALUE1", KEY2: 123 });
		});
		it("should only transform environment variables that are present", () => {
			const env = { KEY1: "value1" } as NodeJS.ProcessEnv;
			const transformations = {
				KEY1: (value: string) => value.toUpperCase(),
				KEY2: (value: string) => Number.parseInt(value, 10),
			};

			const result = transformEnv<Record<string, unknown>>(
				env,
				transformations,
			);

			expect(result).toEqual({ KEY1: "VALUE1" });
		});
	});

	describe("initEnvManager", () => {
		it("should validate and transform environment variables", () => {
			const config = {
				requiredKeys: ["KEY1", "KEY2"] as (keyof AppEnv)[],
				transformations: {
					KEY1: (value: string) => value.toUpperCase(),
					KEY2: (value: string) => Number.parseInt(value, 10),
				},
			};

			// Mock process.env
			const originalEnv = process.env;
			process.env = { KEY1: "value1", KEY2: "123" } as NodeJS.ProcessEnv;

			const result = initEnvManager<Record<string, unknown>>(config);

			expect(result).toEqual({ KEY1: "VALUE1", KEY2: 123 });

			// Restore process.env
			process.env = originalEnv;
		});

		it("should throw an error if a required environment variable is missing", () => {
			const config = {
				requiredKeys: ["KEY1", "KEY2"] as (keyof AppEnv)[],
				transformations: {
					KEY1: (value: string) => value.toUpperCase(),
					KEY2: (value: string) => Number.parseInt(value, 10),
				},
			};

			// Mock process.env
			const originalEnv = process.env;
			process.env = { KEY1: "value1" } as NodeJS.ProcessEnv;

			expect(() => initEnvManager<Record<string, unknown>>(config)).toThrow(
				"Missing required environment variable: KEY2",
			);

			// Restore process.env
			process.env = originalEnv;
		});
	});
});
