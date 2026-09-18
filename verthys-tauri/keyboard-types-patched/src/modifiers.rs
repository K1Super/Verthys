//! Modifier key data.
//!
//! Modifier keys like Shift and Control alter the character value
//! and are used in keyboard shortcuts.
//!
//! Use the constants to match for combinations of the modifier keys.

bitflags::bitflags! {
    /// Pressed modifier keys.
    ///
    /// Specification:
    /// <https://w3c.github.io/uievents-key/#keys-modifier>
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Modifiers: u32 {
        const ALT = 0x01;
        const ALT_GRAPH = 0x2;
        const CAPS_LOCK = 0x4;
        const CONTROL = 0x8;
        const FN = 0x10;
        const FN_LOCK = 0x20;
        const META = 0x40;
        const NUM_LOCK = 0x80;
        const SCROLL_LOCK = 0x100;
        const SHIFT = 0x200;
        const SYMBOL = 0x400;
        const SYMBOL_LOCK = 0x800;
        const HYPER = 0x1000;
        const SUPER = 0x2000;
    }
}

impl Modifiers {
    /// Return `true` if a shift key is pressed.
    pub fn shift(&self) -> bool {
        self.contains(Modifiers::SHIFT)
    }

    /// Return `true` if a control key is pressed.
    pub fn ctrl(&self) -> bool {
        self.contains(Modifiers::CONTROL)
    }

    /// Return `true` if an alt key is pressed.
    pub fn alt(&self) -> bool {
        self.contains(Modifiers::ALT)
    }

    /// Return `true` if a meta key is pressed.
    pub fn meta(&self) -> bool {
        self.contains(Modifiers::META)
    }
}

// 手动实现 serde trait：bitflags! 宏内的 derive(serde::Serialize) 在沙箱环境中不工作，
// bitflags/serde 特性也未正确提供实现，因此手动序列化/反序列化底层 bits: u32 值。
#[cfg(feature = "serde")]
impl serde::Serialize for Modifiers {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Modifiers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Modifiers::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid modifier bits: {:#x}", bits)))
    }
}
