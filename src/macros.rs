//! Macro definitions.

#[doc(hidden)]
#[macro_export]
macro_rules! __item {
    ($i:item) => {
        $i
    };
}

/// Converts struct definition into a C-compatible one.
/// `repr(C)` is added, as well as bitwise-zero `Default` initialization and bitwise-copy `Clone`.
#[macro_export]
macro_rules! impl_struct {
    ($($(#[$outer_meta:meta])* pub struct $s:ident {
        $(
            $(#[$inner_meta:meta])* $v:vis $name:ident: $field:ty,
        )*
    })*) => ($(
        $crate::__item! {
            #[repr(C)]
            $(#[$outer_meta])*
            pub struct $s {
                $($(#[$inner_meta])* $v $name: $field,)*
            }
        }

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

/// Implements `From` an error type for `AttestationError`.
#[macro_export]
macro_rules! map_attestation_error {
    ($($type:ty => $error:path)*) => {
        $(
            impl From<$type> for AttestationError {
                fn from(err: $type) -> Self {
                    $error(err.to_string())
                }
            }
        )*
    };
}
