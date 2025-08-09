use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    extract::{Multipart, Path},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Extension, Router,
};
use chrono::{DateTime, Utc};
use r2d2::{Pool};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tera::{Context, Tera, Value, Result as TeraResult};
use tower_http::services::ServeDir;
use tracing::info;

#[derive(Clone)]
struct AppState {
    templates: Arc<Tera>,
    db: Pool<SqliteConnectionManager>,
    upload_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct Project {
    id: i64,
    title: String,
    summary: String,
    content: String,
    image_path: Option<String>,
    created_at: DateTime<Utc>,
}

fn format_content_filter(value: &Value, _args: &std::collections::HashMap<String, Value>) -> TeraResult<Value> {
    let content = value.as_str().unwrap_or("");
    
    // Convert single line with various separators into formatted HTML
    let formatted = content
        // First handle explicit HTML breaks
        .replace("<br>", "\n")
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        // Handle double spaces as line breaks (common in copy-paste)
        .replace("  ", "\n")
        // Handle various unicode line breaks
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        // Split into lines and process each
        .split('\n')
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return String::new();
            }
            
            // Convert markdown-style formatting
            let mut formatted_line = trimmed.to_string();
            
            // Headers
            if formatted_line.starts_with("# ") {
                formatted_line = format!("<h1>{}</h1>", &formatted_line[2..]);
            } else if formatted_line.starts_with("## ") {
                formatted_line = format!("<h2>{}</h2>", &formatted_line[3..]);
            } else if formatted_line.starts_with("### ") {
                formatted_line = format!("<h3>{}</h3>", &formatted_line[4..]);
            } else if formatted_line.starts_with("#### ") {
                formatted_line = format!("<h4>{}</h4>", &formatted_line[5..]);
            }
            // Lists
            else if formatted_line.starts_with("- ") || formatted_line.starts_with("* ") {
                formatted_line = format!("<li>{}</li>", &formatted_line[2..]);
            }
            // Regular paragraphs (if not a header or list)
            else if !formatted_line.starts_with('<') {
                formatted_line = format!("<p>{}</p>", formatted_line);
            }
            
            // Bold and italic formatting (simple approach for now)
            while formatted_line.contains("**") {
                if let Some(start) = formatted_line.find("**") {
                    if let Some(end) = formatted_line[start+2..].find("**") {
                        let before = &formatted_line[..start];
                        let content = &formatted_line[start+2..start+2+end];
                        let after = &formatted_line[start+4+end..];
                        formatted_line = format!("{}<strong>{}</strong>{}", before, content, after);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
                
            formatted_line
        })
        .collect::<Vec<String>>()
        .join("\n");
    
    Ok(Value::String(formatted))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Ensure required directories exist
    std::fs::create_dir_all("uploads").expect("create uploads dir");
    std::fs::create_dir_all("data").expect("create data dir");

    let manager = SqliteConnectionManager::file("data/acho.sqlite");
    let db_pool = r2d2::Pool::new(manager).expect("failed to create db pool");

    {
        let conn = db_pool.get().expect("db conn");
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                content TEXT NOT NULL,
                image_path TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            INSERT INTO images (project_id, path)
            SELECT p.id, p.image_path
            FROM projects p
            WHERE p.image_path IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM images i WHERE i.project_id = p.id AND i.path = p.image_path
            );
            "#,
        )
        .expect("migrate");
    }

    let mut tera = Tera::new("templates/*.html").expect("init templates");
    tera.autoescape_on(vec![]);
    
    // Add custom filter for formatting content
    tera.register_filter("format_content", format_content_filter);

    let state = AppState {
        templates: Arc::new(tera),
        db: db_pool,
        upload_dir: PathBuf::from("uploads"),
    };

    let app = Router::new()
        .route("/", get(list_projects))
        .route("/projects/:id", get(view_project_handler))
        .route("/admin/new", get(new_project_form))
        .route("/admin/new", post(create_project))
        .route("/admin/edit/:id", get(edit_project_form))
        .route("/admin/edit/:id", post(update_project))
        .route("/admin/delete/:id", post(delete_project))
        .nest_service("/static", ServeDir::new("static"))
        .nest_service("/uploads", ServeDir::new("uploads"))
        .layer(Extension(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn render(state: &AppState, template: &str, ctx: &Context) -> Html<String> {
    let html = state
        .templates
        .render(template, ctx)
        .unwrap_or_else(|e| format!("Template error: {}", e));
    Html(html)
}

async fn list_projects(Extension(state): Extension<AppState>) -> impl IntoResponse {
    let projects: Vec<Project> = {
        let conn = state.db.get().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, title, summary, content, image_path, created_at FROM projects ORDER BY datetime(created_at) DESC",
            )
            .unwrap();
        let projects_iter = stmt
            .query_map([], |row| {
                let created_at_str: String = row.get(5)?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                Ok(Project {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    summary: row.get(2)?,
                    content: row.get(3)?,
                    image_path: row.get(4)?,
                    created_at,
                })
            })
            .unwrap();

        let mut acc: Vec<Project> = vec![];
        for p in projects_iter {
            acc.push(p.unwrap());
        }
        acc
    };

    let mut ctx = Context::new();
    ctx.insert("projects", &projects);
    render(&state, "index.html", &ctx).await.into_response()
}

async fn view_project_handler(Path(id): Path<i64>) -> impl IntoResponse {
    view_project_impl(id).await
}

async fn view_project_impl(id: i64) -> impl IntoResponse {
    // Create database connection
    let manager = r2d2_sqlite::SqliteConnectionManager::file("data/acho.sqlite");
    let db_pool = match r2d2::Pool::new(manager) {
        Ok(pool) => pool,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    
    // Fetch project data first
    let project_data = {
        let conn = match db_pool.get() {
            Ok(conn) => conn,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database connection error").into_response(),
        };
        
        let project_result = conn.query_row(
            "SELECT id, title, summary, content, image_path, created_at FROM projects WHERE id = ?1",
            params![id],
            |row| {
                let created_at_str: String = row.get(5)?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                Ok(Project {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    summary: row.get(2)?,
                    content: row.get(3)?,
                    image_path: row.get(4)?,
                    created_at,
                })
            },
        );
        
        match project_result {
            Ok(project) => Some(project),
            Err(_) => None,
        }
    };
    
    // If project not found, return 404
    let project = match project_data {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "Project not found").into_response(),
    };
    
    // Load all images for this project
    let images_data = {
        let conn = match db_pool.get() {
            Ok(conn) => conn,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database connection error").into_response(),
        };
        
        let mut images: Vec<String> = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT path FROM images WHERE project_id = ?1 ORDER BY id ASC") {
            if let Ok(rows) = stmt.query_map(params![project.id], |row| row.get::<_, String>(0)) {
                for row_result in rows {
                    if let Ok(path) = row_result {
                        images.push(path);
                    }
                }
            }
        }
        images
    };
    
    // Create templates with custom filter
    let templates = match tera::Tera::new("templates/*.html") {
        Ok(mut t) => {
            t.autoescape_on(vec![]);
            t.register_filter("format_content", format_content_filter);
            Arc::new(t)
        },
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response(),
    };
    
    // Now render the response
    let mut ctx = tera::Context::new();
    ctx.insert("project", &project);
    ctx.insert("images", &images_data);
    
    match templates.render("project.html", &ctx) {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Template render error").into_response(),
    }
}

async fn new_project_form(Extension(state): Extension<AppState>) -> impl IntoResponse {
    let ctx = Context::new();
    render(&state, "new.html", &ctx).await.into_response()
}


async fn create_project(Extension(state): Extension<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    let mut title: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut content: Option<String> = None;
    let mut main_image_path: Option<String> = None;
    let mut image_rel_paths: Vec<String> = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "title" => {
                title = Some(field.text().await.unwrap_or_default());
            }
            "summary" => {
                summary = Some(field.text().await.unwrap_or_default());
            }
            "content" => {
                content = Some(field.text().await.unwrap_or_default());
            }
            "main_image" => {
                if let Some(file_name) = field.file_name().map(|s| s.to_string()) {
                    if !file_name.is_empty() {
                        let sanitized = sanitize_filename::sanitize(&file_name);
                        let ext = std::path::Path::new(&sanitized)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        let ts = chrono::Utc::now().timestamp();
                        let uid = uuid::Uuid::new_v4();
                        let new_name = if ext.is_empty() {
                            format!("{}-{}", ts, uid)
                        } else {
                            format!("{}-{}.{}", ts, uid, ext)
                        };
                        let save_path = state.upload_dir.join(&new_name);
                        let bytes = field.bytes().await.unwrap_or_default();
                        tokio::fs::write(&save_path, &bytes).await.unwrap();
                        main_image_path = Some(format!("/uploads/{}", new_name));
                    }
                }
            }
            "image" | "images" => {
                if let Some(file_name) = field.file_name().map(|s| s.to_string()) {
                    let sanitized = sanitize_filename::sanitize(&file_name);
                    let ext = std::path::Path::new(&sanitized)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    let ts = chrono::Utc::now().timestamp();
                    let uid = uuid::Uuid::new_v4();
                    let new_name = if ext.is_empty() {
                        format!("{}-{}", ts, uid)
                    } else {
                        format!("{}-{}.{}", ts, uid, ext)
                    };
                    let save_path = state.upload_dir.join(&new_name);
                    let bytes = field.bytes().await.unwrap_or_default();
                    tokio::fs::write(&save_path, &bytes).await.unwrap();
                    image_rel_paths.push(format!("/uploads/{}", new_name));
                }
            }
            _ => {}
        }
    }

    let title = title.unwrap_or_default();
    if title.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Title is required").into_response();
    }

    let summary = summary.unwrap_or_default();
    let content = content.unwrap_or_default();
    let created_at = Utc::now();

    let conn = state.db.get().unwrap();
    
    conn.execute(
        "INSERT INTO projects (title, summary, content, image_path, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            title,
            summary,
            content,
            main_image_path,
            created_at.to_rfc3339(),
        ],
    )
    .unwrap();
    let id = conn.last_insert_rowid();

    // Insert all images (main image first, then additional images)
    let mut all_images = Vec::new();
    if let Some(main_img) = &main_image_path {
        all_images.push(main_img.clone());
    }
    all_images.extend(image_rel_paths);
    
    if !all_images.is_empty() {
        let tx = conn.unchecked_transaction().unwrap();
        {
            let mut stmt = tx
                .prepare("INSERT INTO images (project_id, path) VALUES (?1, ?2)")
                .unwrap();
            for pth in &all_images {
                stmt.execute(params![id, pth]).unwrap();
            }
        }
        tx.commit().unwrap();
    }

    Redirect::to(&format!("/projects/{}", id)).into_response()
}

async fn delete_project(Path(id): Path<i64>, Extension(state): Extension<AppState>) -> impl IntoResponse {
    let conn = match state.db.get() {
        Ok(conn) => conn,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    
    // Get image paths before deleting project
    let mut image_paths: Vec<String> = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT path FROM images WHERE project_id = ?1") {
        if let Ok(rows) = stmt.query_map(params![id], |row| row.get::<_, String>(0)) {
            for row_result in rows {
                if let Ok(path) = row_result {
                    image_paths.push(path);
                }
            }
        }
    }
    
    // Also get the main image_path from the project
    if let Ok(main_image_path) = conn.query_row(
        "SELECT image_path FROM projects WHERE id = ?1",
        params![id],
        |row| row.get::<_, Option<String>>(0)
    ) {
        if let Some(path) = main_image_path {
            if !image_paths.contains(&path) {
                image_paths.push(path);
            }
        }
    }
    
    // Delete from database (CASCADE will handle images table)
    match conn.execute("DELETE FROM projects WHERE id = ?1", params![id]) {
        Ok(0) => return (StatusCode::NOT_FOUND, "Project not found").into_response(),
        Ok(_) => {
            // Delete physical files
            for path in image_paths {
                if path.starts_with("/uploads/") {
                    let file_path = state.upload_dir.join(&path[9..]); // Remove "/uploads/" prefix
                    let _ = std::fs::remove_file(file_path); // Ignore errors for missing files
                }
            }
        },
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Delete failed").into_response(),
    }
    
    Redirect::to("/").into_response()
}

async fn edit_project_form(Path(id): Path<i64>, Extension(state): Extension<AppState>) -> impl IntoResponse {
    let conn = match state.db.get() {
        Ok(conn) => conn,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    
    let project = match conn.query_row(
        "SELECT id, title, summary, content, image_path, created_at FROM projects WHERE id = ?1",
        params![id],
        |row| {
            let created_at_str: String = row.get(5)?;
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(Project {
                id: row.get(0)?,
                title: row.get(1)?,
                summary: row.get(2)?,
                content: row.get(3)?,
                image_path: row.get(4)?,
                created_at,
            })
        },
    ) {
        Ok(project) => project,
        Err(_) => return (StatusCode::NOT_FOUND, "Project not found").into_response(),
    };
    
    // Get existing images
    let mut images: Vec<String> = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT path FROM images WHERE project_id = ?1 ORDER BY id ASC") {
        if let Ok(rows) = stmt.query_map(params![project.id], |row| row.get::<_, String>(0)) {
            for row_result in rows {
                if let Ok(path) = row_result {
                    images.push(path);
                }
            }
        }
    }
    
    let mut ctx = Context::new();
    ctx.insert("project", &project);
    ctx.insert("images", &images);
    render(&state, "edit.html", &ctx).await.into_response()
}

async fn update_project(Path(id): Path<i64>, Extension(state): Extension<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    let mut title: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut content: Option<String> = None;
    let mut main_image_path: Option<String> = None;
    let mut new_image_paths: Vec<String> = Vec::new();
    let mut keep_existing_images = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "title" => {
                title = Some(field.text().await.unwrap_or_default());
            }
            "summary" => {
                summary = Some(field.text().await.unwrap_or_default());
            }
            "content" => {
                content = Some(field.text().await.unwrap_or_default());
            }
            "keep_images" => {
                keep_existing_images = field.text().await.unwrap_or_default() == "on";
            }
            "main_image" => {
                if let Some(file_name) = field.file_name().map(|s| s.to_string()) {
                    if !file_name.is_empty() {
                        let sanitized = sanitize_filename::sanitize(&file_name);
                        let ext = std::path::Path::new(&sanitized)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        let ts = chrono::Utc::now().timestamp();
                        let uid = uuid::Uuid::new_v4();
                        let new_name = if ext.is_empty() {
                            format!("{}-{}", ts, uid)
                        } else {
                            format!("{}-{}.{}", ts, uid, ext)
                        };
                        let save_path = state.upload_dir.join(&new_name);
                        let bytes = field.bytes().await.unwrap_or_default();
                        tokio::fs::write(&save_path, &bytes).await.unwrap();
                        main_image_path = Some(format!("/uploads/{}", new_name));
                    }
                }
            }
            "image" | "images" => {
                if let Some(file_name) = field.file_name().map(|s| s.to_string()) {
                    if !file_name.is_empty() {
                        let sanitized = sanitize_filename::sanitize(&file_name);
                        let ext = std::path::Path::new(&sanitized)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        let ts = chrono::Utc::now().timestamp();
                        let uid = uuid::Uuid::new_v4();
                        let new_name = if ext.is_empty() {
                            format!("{}-{}", ts, uid)
                        } else {
                            format!("{}-{}.{}", ts, uid, ext)
                        };
                        let save_path = state.upload_dir.join(&new_name);
                        let bytes = field.bytes().await.unwrap_or_default();
                        tokio::fs::write(&save_path, &bytes).await.unwrap();
                        new_image_paths.push(format!("/uploads/{}", new_name));
                    }
                }
            }
            _ => {}
        }
    }

    let title = title.unwrap_or_default();
    if title.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Title is required").into_response();
    }

    let summary = summary.unwrap_or_default();
    let content = content.unwrap_or_default();

    let conn = match state.db.get() {
        Ok(conn) => conn,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };
    
    // If not keeping existing images, delete them
    if !keep_existing_images {
        // Get existing image paths
        let mut old_image_paths: Vec<String> = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT path FROM images WHERE project_id = ?1") {
            if let Ok(rows) = stmt.query_map(params![id], |row| row.get::<_, String>(0)) {
                for row_result in rows {
                    if let Ok(path) = row_result {
                        old_image_paths.push(path);
                    }
                }
            }
        }
        
        // Delete old images from database
        let _ = conn.execute("DELETE FROM images WHERE project_id = ?1", params![id]);
        
        // Delete old image files
        for path in old_image_paths {
            if path.starts_with("/uploads/") {
                let file_path = state.upload_dir.join(&path[9..]);
                let _ = std::fs::remove_file(file_path);
            }
        }
    }
    
    // Update project - use new main image or keep existing
    let preview = if main_image_path.is_some() {
        main_image_path.clone()
    } else if keep_existing_images {
        // Keep existing preview if keeping images
        conn.query_row(
            "SELECT image_path FROM projects WHERE id = ?1",
            params![id],
            |row| row.get::<_, Option<String>>(0)
        ).unwrap_or(None)
    } else {
        None
    };
    
    match conn.execute(
        "UPDATE projects SET title = ?1, summary = ?2, content = ?3, image_path = ?4 WHERE id = ?5",
        params![title, summary, content, preview, id],
    ) {
        Ok(0) => return (StatusCode::NOT_FOUND, "Project not found").into_response(),
        Ok(_) => {},
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Update failed").into_response(),
    }

    // Insert new images (main image first, then additional images)
    let mut all_new_images = Vec::new();
    if let Some(main_img) = &main_image_path {
        all_new_images.push(main_img.clone());
    }
    all_new_images.extend(new_image_paths);
    
    if !all_new_images.is_empty() {
        let tx = conn.unchecked_transaction().unwrap();
        {
            let mut stmt = tx
                .prepare("INSERT INTO images (project_id, path) VALUES (?1, ?2)")
                .unwrap();
            for pth in &all_new_images {
                stmt.execute(params![id, pth]).unwrap();
            }
        }
        tx.commit().unwrap();
    }

    Redirect::to(&format!("/projects/{}", id)).into_response()
}

