//! SDK-3: non-serializable argument fails at compile time with a pointed error.

#[test]
fn sdk3_non_serializable_input_fails_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/sdk3_non_serializable.rs");
}
