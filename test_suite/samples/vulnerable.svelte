<script>
  import { writable, derived } from 'svelte/store';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { setContext, onMount } from 'svelte';
  
  // Hardcoded secrets - should trigger SVELTE-SECRET-001
  const API_KEY = "sk_live_1234567890abcdef";
  const SECRET_TOKEN = "super_secret_key_12345";
  
  // Public environment variable with secret - should trigger SVELTE-ENV-001
  const PUBLIC_API_SECRET = "secret_key_exposed";
  
  // Component props
  export let userContent;
  export let userData;
  export let htmlContent;
  
  // Unsafe writable store without validation - should trigger SVELTE-STORE-001
  const userStore = writable("");
  
  // Derived store with unsafe transformation
  const processedData = derived(userStore, $data => {
    // This would trigger derived store unsafe transform
    document.innerHTML = $data;
    return $data;
  });
  
  // Reactive statements with security issues
  let dynamicCode;
  let userInput;
  let secretData = "password123";
  
  // Reactive eval risk - should trigger SVELTE-REACTIVE-002
  $: result = eval(dynamicCode);
  
  // Reactive DOM manipulation - should trigger SVELTE-REACTIVE-001
  $: if (userInput) {
    document.querySelector('#output').innerHTML = userInput;
  }
  
  // Timing attack in reactive statement
  $: if (performance.now() > 1000) {
    checkPassword(secretData);
  }
  
  // Unsafe context sharing - should trigger SVELTE-CONTEXT-001
  setContext('secrets', { password: 'admin123', token: 'secret_token' });
  
  // Lifecycle with timing attack
  onMount(() => {
    const start = performance.now();
    authenticateUser(secretData);
    const end = performance.now();
    console.log('Auth time:', end - start);
  });
  
  // Unsafe navigation - should trigger SVELTE-NAV-001
  function handleRedirect(url) {
    goto(`/redirect?url=${url}`);
  }
  
  // WebSocket without origin check - should trigger SVELTE-WS-001
  const ws = new WebSocket('ws://localhost:8080');
  
  // EventSource without auth
  const sse = new EventSource('/api/events');
  
  function checkPassword(pwd) {
    // Some password checking logic
  }
  
  function authenticateUser(data) {
    // Authentication logic
  }
</script>

<!-- Template with security vulnerabilities -->

<!-- Unsafe HTML binding - should trigger SVELTE-XSS-001 -->
<div>{@html userContent}</div>

<!-- Critical: User input directly in HTML - should trigger SVELTE-XSS-002 -->
<div>{@html $page.params.content}</div>

<!-- Template injection - should trigger SVELTE-TEMPLATE-001 -->
<h1>Welcome {`User: ${$page.params.username}`}</h1>

<!-- Unsafe event handlers - should trigger SVELTE-EVENT-001 -->
<button on:click={() => eval(userInput)}>Execute</button>
<input on:input={(e) => document.body.innerHTML = e.target.value} />

<!-- Event handler XSS - should trigger SVELTE-EVENT-002 -->
<a href="/profile" on:click="location.href = '/admin' + userInput">Profile</a>

<!-- Route parameter without validation - should trigger SVELTE-ROUTE-001 -->
<div class="user-id">{$page.params.userId}</div>
<script>
  const userId = $page.params.id; // Direct use without validation
</script>

<!-- Unsafe component bindings -->
<input bind:value={htmlContent} />
<div bind:innerHTML={htmlContent}></div>

<!-- Unsafe iteration key -->
{#each items as item, i (i)}
  <div>{item.name}</div>
{/each}

<!-- Conditional rendering with user data -->
{#if $page.params.admin === 'true'}
  <div>Admin panel access granted</div>
{/if}

<style>
  /* Component styles */
  .user-id {
    color: red;
  }
</style>

<!-- SvelteKit specific vulnerabilities would be in separate files -->
<!-- +page.server.js example:

export const actions = {
  // Form action without validation - SVELTE-KIT-001
  default: async ({ request }) => {
    const data = await request.formData();
    const userInput = data.get('input');
    // Direct use without validation
    return { result: userInput };
  }
};

export async function load({ params, url }) {
  // Unsafe load function - SVELTE-KIT-004
  const code = url.searchParams.get('code');
  return {
    data: eval(code) // Dangerous eval in load function
  };
}

-->

<!-- +layout.server.js hooks example:

export async function handle({ event, resolve }) {
  // Handle hook without auth checks - SVELTE-KIT-003
  return await resolve(event); // No authentication or authorization
}

-->

<!-- API endpoint example (+page.server.js):

export async function GET({ request }) {
  // Endpoint without validation - SVELTE-KIT-002
  const data = await request.json();
  // Direct use without sanitization
  return json({ result: data });
}

-->