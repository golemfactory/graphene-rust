#[macro_export]
macro_rules! __item {
    ($i:item) => {
        $i
    };
}

#[macro_export]
macro_rules! impl_struct {
    ($($(#[$attr:meta])* pub struct $s:ident { $(pub $name:ident: $field:ty,)* })*) => ($(
        $crate::__item! {
            #[repr(C)]
            $(#[$attr])*
            pub struct $s {
                $(pub $name: $field,)*
            }
        }

        impl Copy for $s {}

        impl Clone for $s {
            fn clone(&self) -> $s {
                unsafe {
                    std::ptr::read(self)
                }
            }
        }

        impl Default for $s {
            fn default()->$s {
                unsafe {
                    std::mem::transmute([0u8; std::mem::size_of::<$s>()])
                }
            }
        }
    )*)
}
