fn main() {
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
    tauri_build::try_build(attributes).expect("tauri build");
    // Cargo test binaries do not receive the tauri-build Windows resource
    // (embed_resource links it to bin targets only), and rustc's default
    // windows-gnu manifest carries no Common-Controls dependency, so comctl32
    // v6 functions such as TaskDialogIndirect cannot resolve and every test
    // binary fails to start with STATUS_ENTRYPOINT_NOT_FOUND. Link the same
    // Common-Controls v6 manifest resource into every target, including test
    // harness exes. Tauri's identical default manifest is disabled above so
    // the binary links exactly one MANIFEST resource (CVT1100 otherwise).
    let out_dir = std::env::var("OUT_DIR").expect("cargo OUT_DIR");
    let manifest = std::path::Path::new(&out_dir).join("tests.manifest.xml");
    std::fs::write(&manifest, TEST_MANIFEST).expect("write tests.manifest.xml");
    let rc = std::path::Path::new(&out_dir).join("tests.manifest.rc");
    std::fs::write(
        &rc,
        format!(
            "1 24 \"{}\"\n",
            manifest.display().to_string().replace('\\', "\\\\")
        ),
    )
    .expect("write tests.manifest.rc");
    embed_resource::compile_for_everything(&rc, embed_resource::NONE);
}

const TEST_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
"#;
