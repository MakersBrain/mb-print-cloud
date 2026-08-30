// SPDX-License-Identifier: AGPL-3.0-or-later
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts run before this process starts worker threads.
    unsafe { std::env::set_var("PROTOC", protoc) };
    tonic_prost_build::compile_protos("proto/makersbrain/print/agent/v1/agent.proto")?;
    println!("cargo:rerun-if-changed=proto/makersbrain/print/agent/v1/agent.proto");
    Ok(())
}
