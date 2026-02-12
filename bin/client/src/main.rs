#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "sp1")]
pub mod sp1;

fn main() {
    #[cfg(feature = "nitro")]
    {
        return nitro::main();
    }
    
    #[cfg(feature = "sp1")]
    {
        return sp1::main();
    }
}

