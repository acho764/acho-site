## Acho Projects Site

A small personal site to upload electronics and programming projects with text and photos. Backend is in Rust (Axum + SQLite + Tera).

### Features
- Project list and detail pages
- Admin form to create a project
- Image upload stored locally in `uploads/`
- SQLite database in `data/acho.sqlite`

### Prerequisites (local build)
- Rust toolchain (`rustup`)

### Run locally
```bash
# Install Rust if needed
curl https://sh.rustup.rs -sSf | sh

# In a new shell with cargo on PATH
cargo run
# Open http://localhost:3000
```

### Docker
```bash
# Build
docker build -t acho-site .

# Run (bind local folders for persistence)
docker run --rm -p 3000:3000 \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/data:/app/data \
  -e RUST_LOG=info \
  acho-site
# Open http://localhost:3000
```

### Notes
- The `/admin/new` route is open (no auth). If you deploy publicly, put it behind a reverse proxy auth or add a basic auth middleware.
- The `content` field accepts HTML. Be cautious if opening to untrusted users.
