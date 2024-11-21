import path from "node:path";
import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/**/*.ts"],
	format: ["cjs", "esm"],
	dts: true,
	outDir: "dist",
	bundle: false,
	esbuildPlugins: [
		{
			name: "resolve-path-alias",
			setup(build) {
				build.onResolve({ filter: /^@\// }, (args) => ({
					path: path.resolve(__dirname, "src", args.path.replace(/^@\//, "")),
				}));
			},
		},
	],
});
