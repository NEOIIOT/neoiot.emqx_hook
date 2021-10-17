fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .out_dir("src")
        .compile_well_known_types(true)
        .type_attribute(".", "#[derive(Serialize, Deserialize)]")
        .compile(&["proto/exhook.proto"], &["proto"])?;
    Ok(())
}
