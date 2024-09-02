<script lang="ts">
	let { data } = $props();

	let messages: string[] = $state([]);
</script>

{#each messages as message}
	<p>{message}</p>
{/each}
