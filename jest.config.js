module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    globals: {
        'ts-jest': {
            tsconfig: 'tsconfig.test.json',
        },
    },
    testMatch: ['**/tests/**/*.test.ts'],
    collectCoverage: true,
    coverageReporters: ['text', 'lcov'],
};
