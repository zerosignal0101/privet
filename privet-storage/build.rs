fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .compile_protos(&["proto/privet/storage/v1/part_meta.proto"], &["proto"])?;
    Ok(())
}
