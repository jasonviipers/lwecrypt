module.exports = {
	preset: "ts-jest",
	testEnvironment: "node",
	testPathIgnorePatterns: ["/node_modules/", "/build/", "/dist/"],
	testMatch: ['**/__tests__/**/*.ts'],
};
