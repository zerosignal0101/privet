fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new().compile_protos(&["proto/privet/v1/privet.proto"], &["proto"])?;
    Ok(())
}
