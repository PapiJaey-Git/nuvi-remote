//! NUVI Remote brand color palette.

pub type Rgb = (u8, u8, u8);

/// #07080F — Deep obsidian midnight (main app window canvas & viewer backdrop)
pub const BG_CANVAS: Rgb = (7, 8, 15);
/// #11141F — Dark navy slate (cards, modals, toolbar)
pub const SURFACE_CARD: Rgb = (17, 20, 31);
/// #1A1E2C — Charcoal navy (secondary buttons, inputs)
pub const SURFACE_ELEVATED: Rgb = (26, 30, 44);
/// #242938 — Subtle slate hairline border
pub const BORDER_SUBTLE: Rgb = (36, 41, 56);

/// #FF6B3D — Vibrant NUVI coral-orange (primary pill CTAs)
pub const ACCENT_PRIMARY: Rgb = (255, 107, 61);
/// #FF8A63 — Warm coral (wordmark highlight, links, hover)
pub const ACCENT_HIGHLIGHT: Rgb = (255, 138, 99);
/// #352123 — Muted burnt-coral badge fill
pub const ACCENT_TINT: Rgb = (53, 33, 35);
/// #623429 — Warm ember border for consent pop-up attention
pub const ACCENT_GLOW_BORDER: Rgb = (98, 52, 41);

/// #F3F1EC — Warm off-white / alabaster primary text
pub const TEXT_PRIMARY: Rgb = (243, 241, 236);
/// #868B9D — Cool slate gray muted text
pub const TEXT_MUTED: Rgb = (134, 139, 157);

/// #00C950 — Live green status dot
pub const STATUS_ONLINE: Rgb = (0, 201, 80);
/// #E5484D — Harmonized crimson for Decline / Disconnect / Errors
pub const STATUS_DANGER: Rgb = (229, 72, 77);
