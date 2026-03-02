use sp1_build::build_program_with_args;

fn main() {
    if cfg!(feature = "sp1") {
        sp1_build::build_program_with_args(".", sp1_build::BuildArgs {
            docker: std::env::var("SP1_DOCKER").is_ok(),
            ..Default::default()
        });
    }
}