/**
 * Loads environment variables from process.env.
 * @returns {NodeJS.ProcessEnv} The environment variables.
 */
function loadEnv(): NodeJS.ProcessEnv {
	return process.env as NodeJS.ProcessEnv;
}

/**
 * Validates that all required environment variables are present.
 * @param {NodeJS.ProcessEnv} env - The environment variables.
 * @param {string[]} requiredKeys - The keys that are required in the environment variables.
 * @throws {Error} If any required environment variable is missing.
 */
export function validateEnv(
	env: NodeJS.ProcessEnv,
	requiredKeys: string[],
): void {
	for (const key of requiredKeys) {
		if (!env[key]) {
			throw new Error(`Missing required environment variable: ${key}`);
		}
	}
}

/**
 * Transforms the environment variables based on the provided transformations.
 * @param {NodeJS.ProcessEnv} env - The environment variables.
 * @param {Transformations<T>} transformations - The transformations to apply to the environment variables.
 * @returns {T} The transformed environment variables.
 */
export function transformEnv<T extends Record<string, unknown>>(
	env: NodeJS.ProcessEnv,
	transformations: Transformations<T>,
): T {
	const transformedEnv: Partial<T> = {};

	for (const [key, transformFn] of Object.entries(transformations)) {
		if (env[key]) {
			transformedEnv[key as keyof T] = transformFn(env[key] as string);
		}
	}

	return transformedEnv as T;
}

/**
 * Configuration object for the environment manager.
 */
interface EnvConfig<T extends Record<string, unknown>> {
	requiredKeys: (keyof T)[];
	transformations: Transformations<T>;
}

/**
 * Initializes the environment manager with the given configuration.
 * @param {EnvConfig<T>} config - The configuration object containing requiredKeys and transformations.
 * @returns {T} The transformed environment variables.
 * @throws {Error} If any required environment variable is missing.
 */
export function initEnvManager<T extends Record<string, unknown>>(
	config: EnvConfig<T>,
): T {
	const envVars = loadEnv();
	validateEnv(envVars, config.requiredKeys as string[]);
	return transformEnv(envVars, config.transformations);
}

/**
 * Type for transformations.
 */
type Transformations<T extends Record<string, unknown>> = {
	[K in keyof T]: (value: string) => T[K];
};
