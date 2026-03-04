use tla_connect::*;

#[test]
#[ignore] // Requires Apalache
fn test_system_spec_generates_traces() -> TlaResult<()> {
    let config = ApalacheConfig::builder()
        .spec("formal/tla/Nucleus_System.tla")
        .inv("TypeOK")
        .max_traces(5_usize)
        .max_length(25_usize)
        .mode(ApalacheMode::Simulate)
        .build()?;

    let traces = generate_traces(&config)?;
    assert!(!traces.traces.is_empty());

    Ok(())
}
