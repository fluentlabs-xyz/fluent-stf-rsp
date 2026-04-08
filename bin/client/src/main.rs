#[cfg(any(feature = "nitro", feature = "sp1"))]
mod blob;

#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "sp1")]
pub mod sp1;

fn main() {
    #[cfg(feature = "nitro")]
    {
        let _ = nitro::main();
    }

    #[cfg(feature = "sp1")]
    {
        sp1::main();
    }
}
