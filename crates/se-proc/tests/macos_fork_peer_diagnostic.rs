#![cfg(target_os = "macos")]

#[test]
fn native_socket_peer_after_private_single_thread_fork() {
    let script = r#"
import os, socket, struct, json, select
parent, child = socket.socketpair()
creator = os.getpid()
pid = os.fork()
if pid == 0:
    parent.close()
    os.setsid()
    final = os.fork()
    if final > 0:
        os._exit(0)
    child.sendall(struct.pack('i', os.getpid()))
    ready, _, _ = select.select([child], [], [], 5)
    if ready:
        child.recv(1)
    os._exit(0)
child.close()
parent.settimeout(5)
reported = struct.unpack('i', parent.recv(4))[0]
peer = struct.unpack('i', parent.getsockopt(0, 2, 4))[0]
parent.sendall(b'A')
_, status = os.waitpid(pid, 0)
print(json.dumps(dict(creator=creator, launcher=pid, reported=reported, peer=peer, launcher_status=status)))
assert peer == reported and peer != creator and peer != pid and status == 0
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("run isolated native fork diagnostic");
    let root = std::path::Path::new("target/judge-diagnostics");
    std::fs::create_dir_all(root).expect("diagnostic directory");
    std::fs::write(root.join("fork-peer.json"), &output.stdout).expect("diagnostic output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
