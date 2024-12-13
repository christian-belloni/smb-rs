use binrw::PosValue;

/// Create a new `PosValue` with the default value of `T`.
/// 
/// A temporary workaround until `PosValue` has a `Default` implementation in a binrw release.
pub fn pos_value_default<T: std::default::Default>() -> PosValue<T> {
    PosValue {
        pos: u64::default(),
        val: T::default()
    }
}
