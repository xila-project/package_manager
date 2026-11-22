//! Package targets: which device can run a package built for a given target.
//!
//! A target is a Rust target triple, such as `wasm32-wasip1`,
//! `riscv32imc-unknown-none-elf` or `thumbv8m.main-none-eabihf`. A WebAssembly
//! package runs in the Xila virtual machine; any other target is a **native**
//! package, whose code runs directly on the processor.
//!
//! The Xila version declared by the package (see [`crate::compatible`]) is
//! the native application binary interface version: there is no separate
//! number per target.

/// Whether a package built for `package` runs on a device whose target is
/// `device`.
///
/// Equal targets are always compatible. Otherwise everything after the
/// architecture (vendor, operating system and application binary interface,
/// including the floating-point calling convention) must be equal, and the
/// device architecture must provide every instruction the package may use:
///
/// - RISC-V: same width and base (`i` or `e`), the same floating-point
///   extensions (`f`, `d`, `q`, which change the calling convention), and the
///   package's other extensions a subset of the device's (`g` stands for
///   `imafd`). `riscv32imc` runs on `riscv32imac`, not the reverse.
/// - Arm M-profile: `thumbv6m` runs on every later profile, `thumbv7m` on
///   `thumbv7em` and `thumbv8m.main`, and `thumbv8m.base` on `thumbv8m.main`.
///   `thumbv7em` needs a `thumbv7em` device, since the DSP extension is
///   optional in `thumbv8m.main`.
/// - Any other architecture, including WebAssembly and Xtensa, must match
///   exactly.
pub fn target_compatible(package: &str, device: &str) -> bool {
    if package == device {
        return true;
    }
    let (package_architecture, package_rest) = architecture(package);
    let (device_architecture, device_rest) = architecture(device);
    package_rest == device_rest
        && (riscv_compatible(package_architecture, device_architecture)
            || arm_compatible(package_architecture, device_architecture))
}

fn architecture(target: &str) -> (&str, &str) {
    target.split_once('-').unwrap_or((target, ""))
}

/// RISC-V extensions as a bit set (bit `n` is the letter `'a' + n`), with the
/// width and base letter, or `None` when `architecture` is not a plain RISC-V
/// ISA string.
fn riscv(architecture: &str) -> Option<(&str, u8, u32)> {
    let rest = architecture.strip_prefix("riscv")?;
    let (width, letters) = rest.split_at_checked(2)?;
    if width != "32" && width != "64" {
        return None;
    }
    let mut letters = letters.bytes();
    let (base, mut extensions) = match letters.next()? {
        b'g' => (b'i', bits("mafd")),
        base @ (b'i' | b'e') => (base, 0),
        _ => return None,
    };
    for letter in letters {
        if !letter.is_ascii_lowercase() || matches!(letter, b'i' | b'e') {
            return None;
        }
        let bit = 1 << (letter - b'a');
        if extensions & bit != 0 {
            return None;
        }
        extensions |= bit;
    }
    Some((width, base, extensions))
}

const fn bits(letters: &str) -> u32 {
    let letters = letters.as_bytes();
    let mut set = 0;
    let mut index = 0;
    while index < letters.len() {
        set |= 1 << (letters[index] - b'a');
        index += 1;
    }
    set
}

fn riscv_compatible(package: &str, device: &str) -> bool {
    const FLOATING_POINT: u32 = bits("fdq");
    match (riscv(package), riscv(device)) {
        (
            Some((package_width, package_base, package)),
            Some((device_width, device_base, device)),
        ) => {
            package_width == device_width
                && package_base == device_base
                && package & FLOATING_POINT == device & FLOATING_POINT
                && package & !device == 0
        }
        _ => false,
    }
}

fn arm_compatible(package: &str, device: &str) -> bool {
    matches!(
        (package, device),
        (
            "thumbv6m",
            "thumbv7m" | "thumbv7em" | "thumbv8m.base" | "thumbv8m.main"
        ) | ("thumbv7m", "thumbv7em" | "thumbv8m.main")
            | ("thumbv8m.base", "thumbv8m.main")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_target_compatibility() {
        for (package, device, expected) in [
            ("wasm32-wasip1", "wasm32-wasip1", true),
            ("wasm32-wasip1", "wasm32-wasip2", false),
            // RISC-V: subsets of the device's extensions.
            (
                "riscv32imc-unknown-none-elf",
                "riscv32imac-unknown-none-elf",
                true,
            ),
            (
                "riscv32imac-unknown-none-elf",
                "riscv32imc-unknown-none-elf",
                false,
            ),
            (
                "riscv32i-unknown-none-elf",
                "riscv32imc-unknown-none-elf",
                true,
            ),
            (
                "riscv64imac-unknown-none-elf",
                "riscv64gc-unknown-none-elf",
                false,
            ),
            (
                "riscv64gc-unknown-none-elf",
                "riscv64gc-unknown-none-elf",
                true,
            ),
            (
                "riscv32imafc-unknown-none-elf",
                "riscv32imafdc-unknown-none-elf",
                false,
            ),
            // Floating-point extensions change the calling convention.
            (
                "riscv32imac-unknown-none-elf",
                "riscv32imafc-unknown-none-elf",
                false,
            ),
            // Different width, base or operating system.
            (
                "riscv32imc-unknown-none-elf",
                "riscv64imac-unknown-none-elf",
                false,
            ),
            (
                "riscv32emc-unknown-none-elf",
                "riscv32imc-unknown-none-elf",
                false,
            ),
            (
                "riscv32imc-unknown-none-elf",
                "riscv32imac-esp-espidf",
                false,
            ),
            // Malformed RISC-V names only match exactly.
            (
                "riscv32imm-unknown-none-elf",
                "riscv32imac-unknown-none-elf",
                false,
            ),
            (
                "riscv32-unknown-none-elf",
                "riscv32imac-unknown-none-elf",
                false,
            ),
            // Arm M-profile.
            ("thumbv6m-none-eabi", "thumbv7em-none-eabi", true),
            ("thumbv6m-none-eabi", "thumbv8m.base-none-eabi", true),
            ("thumbv7m-none-eabi", "thumbv8m.main-none-eabi", true),
            ("thumbv8m.base-none-eabi", "thumbv8m.main-none-eabi", true),
            ("thumbv7em-none-eabi", "thumbv8m.main-none-eabi", false),
            ("thumbv7em-none-eabi", "thumbv7m-none-eabi", false),
            ("thumbv7m-none-eabi", "thumbv7em-none-eabihf", false),
            ("thumbv8m.base-none-eabi", "thumbv7m-none-eabi", false),
            // Other architectures match exactly.
            ("xtensa-esp32-none-elf", "xtensa-esp32s3-none-elf", false),
            ("xtensa-esp32s3-none-elf", "xtensa-esp32s3-none-elf", true),
            ("wasm32-wasip1", "riscv32imac-unknown-none-elf", false),
        ] {
            assert_eq!(
                target_compatible(package, device),
                expected,
                "{package} on {device}"
            );
        }
    }
}
