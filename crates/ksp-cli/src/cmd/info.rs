//! `ksp info` — System and protocol information.

use crate::ui;

pub fn run(json: bool) {
    if !json {
        ui::print_header("KSP System Information");
    }

    let sys = sysinfo::System::new_all();

    let os_name = sysinfo::System::name().unwrap_or_else(|| "Unknown".into());
    let os_version = sysinfo::System::os_version().unwrap_or_else(|| "Unknown".into());
    let cpu_brand = sys
        .cpus()
        .first()
        .map(|c| c.brand().to_string())
        .unwrap_or_else(|| "Unknown".into());
    let cpu_count = sys.cpus().len();
    let total_mem = sys.total_memory();

    #[cfg(target_arch = "x86_64")]
    let aesni = is_x86_feature_detected!("aes");
    #[cfg(not(target_arch = "x86_64"))]
    let aesni = false;

    #[cfg(target_arch = "x86_64")]
    let avx2 = is_x86_feature_detected!("avx2");
    #[cfg(not(target_arch = "x86_64"))]
    let avx2 = false;

    if json {
        ui::json_output(&serde_json::json!({
            "cli_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": ksp_core::CURRENT_VERSION.to_string(),
            "os": format!("{} {}", os_name, os_version),
            "cpu": cpu_brand,
            "cpu_cores": cpu_count,
            "memory": total_mem,
            "aes_ni": aesni,
            "avx2": avx2,
            "arch": std::env::consts::ARCH,
        }));
    } else {
        let mut t = ui::table(&["Property", "Value"]);
        t.add_row(vec![
            "KSP CLI Version",
            &format!("v{}", env!("CARGO_PKG_VERSION")),
        ]);
        t.add_row(vec![
            "Protocol Version",
            &format!("KSP v{}", ksp_core::CURRENT_VERSION),
        ]);
        t.add_row(vec!["OS", &format!("{} {}", os_name, os_version)]);
        t.add_row(vec!["Architecture", std::env::consts::ARCH]);
        t.add_row(vec!["CPU", &cpu_brand]);
        t.add_row(vec!["CPU Cores", &cpu_count.to_string()]);
        t.add_row(vec!["Memory", &ui::format_bytes(total_mem)]);
        t.add_row(vec![
            "AES-NI",
            if aesni {
                "✔ Supported"
            } else {
                "✘ Not detected"
            },
        ]);
        t.add_row(vec![
            "AVX2",
            if avx2 {
                "✔ Supported"
            } else {
                "✘ Not detected"
            },
        ]);
        println!("{t}");
    }
}
