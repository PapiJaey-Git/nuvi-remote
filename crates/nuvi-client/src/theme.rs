use egui::{Color32, CornerRadius, Margin, Pos2, Rect, RichText, Stroke, Vec2};
use nuvi_proto::brand;

pub fn c(rgb: brand::Rgb) -> Color32 {
    Color32::from_rgb(rgb.0, rgb.1, rgb.2)
}

pub const NUVI_LOGO_PNG: &[u8] = include_bytes!("../../../assets/nuvi-logo.png");

/// Official NUVI Solutions window & taskbar icon decoded from `assets/nuvi-logo.png`.
pub fn nuvi_window_icon() -> egui::IconData {
    let decoded = image::load_from_memory(NUVI_LOGO_PNG)
        .expect("embedded nuvi-logo.png should be valid PNG")
        .resize_exact(64, 64, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    egui::IconData {
        rgba: decoded.into_raw(),
        width: 64,
        height: 64,
    }
}

pub fn apply_nuvi_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();

    style.visuals.window_fill = c(brand::BG_CANVAS);
    style.visuals.panel_fill = c(brand::BG_CANVAS);
    style.visuals.faint_bg_color = c(brand::SURFACE_CARD);
    style.visuals.extreme_bg_color = c(brand::SURFACE_ELEVATED);
    style.visuals.code_bg_color = c(brand::SURFACE_ELEVATED);

    style.visuals.widgets.noninteractive.bg_fill = c(brand::SURFACE_CARD);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE));
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, c(brand::TEXT_PRIMARY));
    style.visuals.widgets.noninteractive.corner_radius = CornerRadius::same(10);

    style.visuals.widgets.inactive.bg_fill = c(brand::SURFACE_ELEVATED);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE));
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, c(brand::TEXT_PRIMARY));
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(16);

    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 43, 62);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, c(brand::ACCENT_HIGHLIGHT));
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, c(brand::TEXT_PRIMARY));
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(16);

    style.visuals.widgets.active.bg_fill = c(brand::ACCENT_TINT);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, c(brand::ACCENT_PRIMARY));
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, c(brand::TEXT_PRIMARY));
    style.visuals.widgets.active.corner_radius = CornerRadius::same(16);

    style.visuals.selection.bg_fill = c(brand::ACCENT_TINT);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, c(brand::ACCENT_PRIMARY));

    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(14.0, 7.0);

    ctx.set_style(style);
}

pub fn draw_nuvi_logo_mark(ui: &mut egui::Ui, size: f32) {
    let tex_id = egui::Id::new("nuvi_brand_logo_tex");
    let existing = ui.ctx().data(|d| d.get_temp::<egui::TextureHandle>(tex_id));
    let tex = match existing {
        Some(t) => t,
        None => {
            let decoded = image::load_from_memory(NUVI_LOGO_PNG)
                .expect("embedded nuvi-logo.png should be valid PNG")
                .to_rgba8();
            let w = decoded.width() as usize;
            let h = decoded.height() as usize;
            let color_img = egui::ColorImage::from_rgba_unmultiplied([w, h], &decoded.into_raw());
            let handle =
                ui.ctx()
                    .load_texture("nuvi_brand_logo", color_img, egui::TextureOptions::LINEAR);
            ui.ctx().data_mut(|d| d.insert_temp(tex_id, handle.clone()));
            handle
        }
    };
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    egui::Image::from_texture((tex.id(), Vec2::splat(size)))
        .corner_radius(CornerRadius::same(6))
        .paint_at(ui, rect);
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(6),
        Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)),
        egui::StrokeKind::Inside,
    );
}

pub fn nuvi_header(ui: &mut egui::Ui, status_text: &str, live: bool) {
    ui.horizontal(|ui| {
        draw_nuvi_logo_mark(ui, 26.0);
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.label(
                RichText::new("NUVI ")
                    .size(20.0)
                    .strong()
                    .color(c(brand::TEXT_PRIMARY)),
            );
            ui.label(
                RichText::new("Remote.")
                    .size(20.0)
                    .strong()
                    .color(c(brand::ACCENT_HIGHLIGHT)),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            status_pill(ui, status_text, live);
        });
    });
}

pub fn status_pill(ui: &mut egui::Ui, label: &str, online: bool) {
    let dot_color = if online {
        c(brand::STATUS_ONLINE)
    } else {
        c(brand::TEXT_MUTED)
    };
    egui::Frame::new()
        .fill(c(brand::BG_CANVAS))
        .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(Margin::symmetric(12, 5))
        .show(ui, |ui| {
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, dot_color);
                ui.label(
                    RichText::new(label)
                        .size(11.5)
                        .strong()
                        .color(c(brand::TEXT_PRIMARY)),
                );
            });
        });
}

pub fn badge_pill(ui: &mut egui::Ui, text: &str, bg: Color32, fg: Color32) {
    egui::Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(10.5).strong().color(fg));
        });
}

pub fn draw_progress_bar(ui: &mut egui::Ui, fraction: f32, fill_color: Color32) {
    let width = ui.available_width().max(40.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 5.0), egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(3), c(brand::SURFACE_ELEVATED));
    let frac = fraction.clamp(0.0, 1.0);
    if frac > 0.0 {
        let fill_rect = Rect::from_min_size(rect.min, Vec2::new(rect.width() * frac, rect.height()));
        p.rect_filled(fill_rect, CornerRadius::same(3), fill_color);
    }
}

pub fn segmented_tab_button(ui: &mut egui::Ui, active: bool, label: &str) -> egui::Response {
    let (fill, stroke, text_color) = if active {
        (
            c(brand::ACCENT_TINT),
            Stroke::new(1.0_f32, c(brand::ACCENT_PRIMARY)),
            c(brand::ACCENT_HIGHLIGHT),
        )
    } else {
        (
            c(brand::SURFACE_CARD),
            Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)),
            c(brand::TEXT_MUTED),
        )
    };
    let btn = egui::Button::new(RichText::new(label).size(12.5).strong().color(text_color))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(16));
    ui.add(btn)
}

/// Flat text tab with a coral bottom underline when active.
pub fn nuvi_flat_tab(ui: &mut egui::Ui, active: bool, label: &str) -> egui::Response {
    let text_color = if active {
        c(brand::ACCENT_PRIMARY)
    } else {
        c(brand::TEXT_MUTED)
    };
    let resp = ui.add(
        egui::Button::new(RichText::new(label).size(12.5).strong().color(text_color))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::ZERO),
    );
    if active {
        let r = resp.rect;
        ui.painter().line_segment(
            [
                Pos2::new(r.left() + 4.0, r.bottom() - 1.0),
                Pos2::new(r.right() - 4.0, r.bottom() - 1.0),
            ],
            Stroke::new(2.0_f32, c(brand::ACCENT_PRIMARY)),
        );
    }
    resp
}

/// Full-width slim coral status ribbon banner.
pub fn nuvi_ribbon_banner(ui: &mut egui::Ui, text: &str) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 24.0), egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::ZERO, c(brand::ACCENT_PRIMARY));
    p.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::FontId::proportional(11.5),
        c(brand::BG_CANVAS),
    );
}

/// Compact Metro-style feature tile in NUVI colors.
pub fn nuvi_feature_tile(
    ui: &mut egui::Ui,
    size: Vec2,
    bg: Color32,
    title: &str,
    body: &str,
    footer_cta: &str,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(4), bg);
    let border = if resp.hovered() {
        c(brand::ACCENT_HIGHLIGHT)
    } else {
        c(brand::BORDER_SUBTLE)
    };
    p.rect_stroke(
        rect,
        CornerRadius::same(4),
        Stroke::new(1.0_f32, border),
        egui::StrokeKind::Inside,
    );
    p.text(
        Pos2::new(rect.left() + 12.0, rect.top() + 12.0),
        egui::Align2::LEFT_TOP,
        title,
        egui::FontId::proportional(13.5),
        c(brand::TEXT_PRIMARY),
    );
    p.text(
        Pos2::new(rect.left() + 12.0, rect.top() + 34.0),
        egui::Align2::LEFT_TOP,
        body,
        egui::FontId::proportional(11.0),
        c(brand::TEXT_PRIMARY).linear_multiply(0.82),
    );
    p.text(
        Pos2::new(rect.right() - 10.0, rect.bottom() - 10.0),
        egui::Align2::RIGHT_BOTTOM,
        footer_cta,
        egui::FontId::proportional(11.0),
        c(brand::ACCENT_HIGHLIGHT),
    );
    resp
}

pub fn nuvi_card<R>(
    ui: &mut egui::Ui,
    glow_border: bool,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    let stroke_color = if glow_border {
        c(brand::ACCENT_GLOW_BORDER)
    } else {
        c(brand::BORDER_SUBTLE)
    };
    egui::Frame::new()
        .fill(c(brand::SURFACE_CARD))
        .stroke(Stroke::new(1.0_f32, stroke_color))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(14))
        .show(ui, add_contents)
}

/// Hero card with a 3px coral left accent stripe.
#[allow(dead_code)]
pub fn hero_id_card<R>(
    ui: &mut egui::Ui,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    let resp = nuvi_card(ui, true, add_contents);
    let r = resp.response.rect;
    let stripe = Rect::from_min_max(
        Pos2::new(r.left() + 1.0, r.top() + 10.0),
        Pos2::new(r.left() + 4.0, r.bottom() - 10.0),
    );
    ui.painter()
        .rect_filled(stripe, CornerRadius::same(2), c(brand::ACCENT_PRIMARY));
    resp
}

pub fn primary_pill_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label)
            .strong()
            .color(c(brand::BG_CANVAS)),
    )
    .fill(c(brand::ACCENT_PRIMARY))
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(18));
    ui.add(btn)
}

pub fn secondary_pill_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).color(c(brand::TEXT_PRIMARY)))
        .fill(c(brand::SURFACE_ELEVATED))
        .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
        .corner_radius(CornerRadius::same(18));
    ui.add(btn)
}

pub fn danger_pill_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label)
            .strong()
            .color(c(brand::TEXT_PRIMARY)),
    )
    .fill(c(brand::STATUS_DANGER))
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(18));
    ui.add(btn)
}
