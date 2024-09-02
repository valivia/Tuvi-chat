<script lang="ts">
	let { children } = $props();
</script>

<svelte:head>
	<meta name="theme-color" content="#bf8d50" />
</svelte:head>

{@render children()}

<style lang="scss" global>
	@import "../styles/global.scss";
</style>
