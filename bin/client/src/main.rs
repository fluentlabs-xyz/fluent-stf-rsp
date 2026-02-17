#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "sp1")]
pub mod sp1;

fn main() {
    #[cfg(feature = "nitro")]
    {
        nitro::main();
    }
    
    #[cfg(feature = "sp1")]
    {
        sp1::main();
    }
}

