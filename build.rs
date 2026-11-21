fn main() {
    // Sematkan manifest: tema modern, DPI-aware, minta hak Administrator (UAC) saat dibuka.
    embed_resource::compile("app.rc", embed_resource::NONE);
}
