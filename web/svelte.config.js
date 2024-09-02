import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),

	kit: {
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: undefined,
			precompress: true,
			strict: true
		}),

		alias: {
			"styles": "./src/styles",
			"components": "./src/components",
			"lib": "./src/lib",
			"routes": "./src/routes",
		}
	}
};

export default config;
