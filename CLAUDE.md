# Acho Site - Project Portfolio

A Rust web application for showcasing projects with image galleries, built with Axum and SQLite.

## Features

- **Project Management**: Full CRUD operations for projects
- **Multi-Image Gallery**: Upload and display multiple images per project
- **Content Formatting**: Single-line markdown-style content that displays as formatted HTML
- **Authentication**: Basic auth for admin operations
- **Docker Support**: Containerized deployment

## Tech Stack

- **Backend**: Rust with Axum 0.6 web framework
- **Database**: SQLite with r2d2 connection pooling
- **Templates**: Tera templating engine with custom filters
- **Styling**: Custom CSS with dark theme
- **Containerization**: Multi-stage Docker build

## Development Commands

```bash
# Build and run Docker container
docker build -t acho-site .
docker run --rm -p 3000:3000 -v "$PWD/uploads:/app/uploads" -v "$PWD/data:/app/data" -e RUST_LOG=info -e ADMIN_USER=admin -e ADMIN_PASS=Aa6812121101 acho-site

# Local development
cargo run
```

## API Endpoints

- `GET /` - List all projects
- `GET /projects/:id` - View individual project with gallery
- `GET /admin/new` - New project form (auth required)
- `POST /admin/new` - Create project (auth required)
- `GET /admin/edit/:id` - Edit project form (auth required)  
- `POST /admin/edit/:id` - Update project (auth required)
- `POST /admin/delete/:id` - Delete project (auth required)

## Database Schema

```sql
CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    content TEXT NOT NULL,
    image_path TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);
```

## Content Formatting

The application includes a custom Tera filter `format_content` that converts single-line markdown-style formatting to HTML:

- `# Title` → `<h1>Title</h1>`
- `## Subtitle` → `<h2>Subtitle</h2>`
- `**bold text**` → `<strong>bold text</strong>`
- `- List item` → `<li>List item</li>`
- Regular text → `<p>Regular text</p>`

## Authentication

Admin operations require Basic Authentication:
- Username: Set via `ADMIN_USER` env var (default: "admin")
- Password: Set via `ADMIN_PASS` env var (default: "admin")

## File Storage

- Images uploaded to `/uploads` directory
- Database stored in `/data/acho.sqlite`
- Both directories are Docker volumes for persistence

## Recent Updates

- Added full edit/delete functionality for projects
- Implemented custom content formatting filter
- Enhanced gallery support with multiple images
- Added professional UI styling with action buttons
- Fixed SQLite async compatibility issues