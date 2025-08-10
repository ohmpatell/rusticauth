use tera::{Tera, Context};
use actix_web::{HttpResponse, Result};
use serde::Serialize;


// template engine
pub fn init_templates() -> Tera {
    match Tera::new("templates/**/*") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error initializing template engine: {}", e);
            std::process::exit(1);
        }
    }
}

pub fn render_template<T: Serialize>(templates: &Tera, template_name: &str, context: &T) -> Result<HttpResponse> {
    let mut ctx = Context::new();
    ctx.insert("data", context);

    match templates.render(template_name, &ctx) {
        Ok(rendered) => Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(rendered)),
        Err(e) => {
            eprintln!("Template rendering error: {}", e);
            Ok(HttpResponse::InternalServerError()
                .body("Template rendering failed"))
        }
    }
}

// secure csrf token
pub fn generate_csrf_token() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();

    let random : u64= rng.gen();
    format!("csrf_{:016x}", random)
}