#[test]
fn tcp_close_cleans_all_socket_request_state() {
    let source = include_str!("../../sword-ebpf/src/network/tcp.rs");
    let function_start = source
        .find("fn cleanup_socket_request_state")
        .expect("socket cleanup helper must exist");
    let cleanup = &source[function_start..];
    let function_end = cleanup.find("\n}").expect("socket cleanup helper must end");
    let cleanup = &cleanup[..function_end];

    for map in [
        "TCP_REQUEST_START",
        "TCP_PAYLOAD_ARRIVAL",
        "TCP_ACTIVE_FLOWS",
        "HTTP_REQUEST_HEADS",
    ] {
        assert!(
            cleanup.contains(&format!("{map}.remove(&socket_key)")),
            "{map} must be removed when a socket closes"
        );
    }

    assert!(
        source.contains(
            "if new_state == BPF_TCP_CLOSE {\n            cleanup_socket_request_state(skaddr);"
        ),
        "TCP_CLOSE must invoke the socket cleanup helper"
    );
}
