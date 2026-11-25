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
    let btn = egui::Button::new(RichText::new(label).size(12.0).strong().color(text_color))
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

/// Sharp-modern Metro-style feature tile.
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
        c(brand::TEXT_PRIMARY).linear_multiply(0.84),
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

/// `Recent Sessions` 16:10 thumbnail card.
/// Returns `(card_response, star_clicked)`.
#[allow(clippy::too_many_arguments)]
pub fn nuvi_session_tile(
    ui: &mut egui::Ui,
    size: Vec2,
    thumb_tex: Option<&egui::TextureHandle>,
    device_id: &str,
    title: &str,
    online: bool,
    is_service: bool,
    is_unattended: bool,
    is_favorite: bool,
    selected: bool,
) -> (egui::Response, bool) {
    let (rect, card_resp) = ui.allocate_exact_size(size, egui::Sense::click());
    let star_rect = Rect::from_min_size(
        Pos2::new(rect.right() - 26.0, rect.top() + 4.0),
        Vec2::new(22.0, 22.0),
    );
    let star_resp = ui.interact(
        star_rect,
        ui.make_persistent_id(("star", device_id)),
        egui::Sense::click(),
    );

    let p = ui.painter();
    if let Some(tex) = thumb_tex {
        p.image(
            tex.id(),
            rect,
            Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
            Color32::WHITE,
        );
    } else {
        // Obsidian geometric fallback wallpaper
        p.rect_filled(rect, CornerRadius::same(4), Color32::from_rgb(13, 16, 27));
        let accent_tri = Rect::from_min_size(
            Pos2::new(rect.left() + 18.0, rect.top() + 20.0),
            Vec2::new(size.x * 0.45, size.y * 0.45),
        );
        p.rect_filled(accent_tri, CornerRadius::same(4), c(brand::SURFACE_CARD));
        let accent_win = Rect::from_min_size(
            Pos2::new(rect.left() + size.x * 0.36, rect.top() + 28.0),
            Vec2::new(size.x * 0.42, size.y * 0.38),
        );
        p.rect_filled(accent_win, CornerRadius::same(4), c(brand::SURFACE_ELEVATED));
    }

    // Outer border
    let border = if selected || card_resp.hovered() {
        c(brand::ACCENT_PRIMARY)
    } else {
        c(brand::BORDER_SUBTLE)
    };
    p.rect_stroke(
        rect,
        CornerRadius::same(4),
        Stroke::new(1.0_f32, border),
        egui::StrokeKind::Inside,
    );

    // Top-left status badge dot
    let dot_bg = Pos2::new(rect.left() + 12.0, rect.top() + 12.0);
    p.circle_filled(dot_bg, 7.0, Color32::from_rgba_unmultiplied(7, 8, 15, 210));
    p.circle_filled(
        dot_bg,
        4.2,
        if online {
            c(brand::STATUS_ONLINE)
        } else {
            c(brand::STATUS_DANGER)
        },
    );

    // Top-right star
    let star_glyph = if is_favorite { "★" } else { "☆" };
    let star_col = if is_favorite || star_resp.hovered() {
        c(brand::ACCENT_PRIMARY)
    } else {
        c(brand::TEXT_PRIMARY)
    };
    p.text(
        star_rect.center(),
        egui::Align2::CENTER_CENTER,
        star_glyph,
        egui::FontId::proportional(14.0),
        star_col,
    );

    // Bottom semi-transparent dark overlay strip
    let strip_h = 30.0;
    let strip = Rect::from_min_max(
        Pos2::new(rect.left() + 1.0, rect.bottom() - strip_h),
        Pos2::new(rect.right() - 1.0, rect.bottom() - 1.0),
    );
    p.rect_filled(
        strip,
        CornerRadius {
            nw: 0,
            ne: 0,
            sw: 4,
            se: 4,
        },
        Color32::from_rgba_unmultiplied(7, 8, 15, 215),
    );

    let display_txt = if card_resp.hovered() && title != device_id {
        title
    } else {
        device_id
    };
    p.text(
        Pos2::new(strip.left() + 8.0, strip.center().y),
        egui::Align2::LEFT_CENTER,
        display_txt,
        egui::FontId::monospace(11.0),
        c(brand::TEXT_PRIMARY),
    );

    let tag = if is_service && is_unattended {
        "SVC·KEY"
    } else if is_service {
        "SVC"
    } else if is_unattended {
        "KEY"
    } else {
        ""
    };
    if !tag.is_empty() {
        p.text(
            Pos2::new(strip.right() - 8.0, strip.center().y),
            egui::Align2::RIGHT_CENTER,
            tag,
            egui::FontId::proportional(9.5),
            c(brand::ACCENT_HIGHLIGHT),
        );
    }

    if selected || card_resp.hovered() {
        p.line_segment(
            [
                Pos2::new(rect.left() + 1.0, rect.bottom() - 1.5),
                Pos2::new(rect.right() - 1.0, rect.bottom() - 1.5),
            ],
            Stroke::new(2.0_f32, c(brand::ACCENT_PRIMARY)),
        );
    }

    (card_resp, star_resp.clicked())
}

pub fn nuvi_card<R>(
    ui: &mut egui::Ui,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    egui::Frame::new()
        .fill(c(brand::SURFACE_CARD))
        .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(14))
        .show(ui, add_contents)
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
