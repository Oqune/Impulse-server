fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=assets/brand/impulse.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/brand/impulse.ico")
            .set("ProductName", "Impulse Server")
            .set("FileDescription", "Impulse Server - sovereign LAN relay")
            .set("OriginalFilename", "impulse-server.exe")
            .compile()?;
    }
    Ok(())
}
