#[cfg(feature = "sp1")]
use sp1_build::build_program;

fn main() {
    #[cfg(feature = "sp1")]
    build_program("../client");
}
