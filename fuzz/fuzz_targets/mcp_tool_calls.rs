#![no_main]

use libfuzzer_sys::fuzz_target;

// `mcp::classify` (the JSON-RPC tool-name extraction behind `McpToolScopes`)
// on an arbitrary request body, against `serde_json::Value` as an oracle.
fuzz_target!(|body: &[u8]| {
    oauth_resource_server::__fuzz::mcp_tool_calls(body);
});
