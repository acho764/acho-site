# Acho Site - Project Portfolio

A Rust web application for showcasing projects with image galleries, built with Axum and SQLite.

## Features

- **Project Management**: Full CRUD operations for projects (no authentication required)
- **Multi-Image Gallery**: Upload and display multiple images per project
- **Main Image Support**: Separate upload field for hero/preview image
- **Content Formatting**: Single-line markdown-style content that displays as formatted HTML
- **Image Modal Gallery**: Click images to open fullscreen gallery with navigation
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
docker run --rm -p 3000:3000 -v "$PWD/uploads:/app/uploads" -v "$PWD/data:/app/data" -e RUST_LOG=info acho-site

# Local development
cargo run
```

## API Endpoints

- `GET /` - List all projects
- `GET /projects/:id` - View individual project with gallery
- `GET /admin/new` - New project form
- `POST /admin/new` - Create project
- `GET /admin/edit/:id` - Edit project form
- `POST /admin/edit/:id` - Update project
- `POST /admin/delete/:id` - Delete project

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

## Image Management

### Upload Fields
- **Main Image**: Single upload for hero/preview image (stored in `projects.image_path`)
- **Additional Images**: Multiple uploads for gallery images

### Gallery Features
- **Modal Viewer**: Click any image to open fullscreen gallery
- **Navigation**: Previous/Next buttons and keyboard arrows
- **Image Counter**: Shows current position (e.g., "2 / 5")
- **Keyboard Controls**: 
  - Arrow keys to navigate
  - Escape to close

## Content Formatting

The application includes a custom Tera filter `format_content` that converts single-line markdown-style formatting to HTML:

- `# Title` → `<h1>Title</h1>`
- `## Subtitle` → `<h2>Subtitle</h2>`
- `**bold text**` → `<strong>bold text</strong>`
- `- List item` → `<li>List item</li>`
- Regular text → `<p>Regular text</p>`

## File Storage

- Images uploaded to `/uploads` directory
- Database stored in `/data/acho.sqlite`
- Both directories are Docker volumes for persistence

## Recent Updates

- **Removed Authentication**: Admin operations no longer require authentication
- **Enhanced Image Management**: Separate main image and gallery image uploads
- **Interactive Gallery**: Modal viewer with navigation and keyboard controls
- **Improved Error Handling**: Better multipart form parsing
- **Content Formatting**: Custom filter for markdown-style single-line content
- **Professional UI**: Edit/delete buttons, modern styling, responsive design