// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Procedurally drawn tray icon (no image decoder needed): a blue disc with a
//! white key. Returned as RGBA (Windows) or ARGB big-endian (StatusNotifier).

pub fn rgba(size: u32) -> Vec<u8> {
    let s = size as f32;
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    let (cx, cy) = (s / 2.0, s / 2.0);
    let radius = s * 0.22; // rounded tile corners
    let inside_tile = |px: f32, py: f32| -> f32 {
        // signed distance to a rounded square tile of half-size h
        let h = s / 2.0 - 0.5;
        let dx = (px - cx).abs() - (h - radius);
        let dy = (py - cy).abs() - (h - radius);
        let outside =
            (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt() + dx.max(dy).min(0.0) - radius;
        -outside
    };
    let blocks = [
        (0.345, 0.655, 0.585, 0.670),
        (0.385, 0.615, 0.475, 0.560),
        (0.425, 0.575, 0.365, 0.450),
    ]; // x0,x1,y0,y1 fractions, bottom to top
    let ring_c = (s * 0.655, s * 0.315);
    let ring_r = s * 0.075;
    for y in 0..size {
        for x in 0..size {
            let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
            let d = inside_tile(px, py);
            let mut rgba = [0u8, 0, 0, 0];
            if d > -1.0 {
                let a = ((d + 1.0).clamp(0.0, 1.0) * 255.0) as u8;
                // gradient blue tile
                let t = (px + py) / (2.0 * s);
                let r = (0x2f as f32 * (1.0 - t) + 0x1b as f32 * t) as u8;
                let g = (0x5f as f32 * (1.0 - t) + 0x3a as f32 * t) as u8;
                let b = (0xe0 as f32 * (1.0 - t) + 0x9a as f32 * t) as u8;
                rgba = [r, g, b, a];
                for (i, (x0, x1, y0, y1)) in blocks.iter().enumerate() {
                    if px >= s * x0 && px <= s * x1 && py >= s * y0 && py <= s * y1 {
                        let w = [0xf2u8, 0xd9, 0xbf][i];
                        rgba = [w, w, w.max(0xd0), a];
                    }
                }
                let dr = ((px - ring_c.0).powi(2) + (py - ring_c.1).powi(2)).sqrt();
                let ring = dr <= ring_r + s * 0.035 && dr >= ring_r - s * 0.035;
                // key shaft from ring towards lower-left
                let (sx, sy) = (ring_c.0 - s * 0.05, ring_c.1 + s * 0.05);
                let (ex, ey) = (s * 0.5, s * 0.47);
                let (vx, vy) = (ex - sx, ey - sy);
                let len2 = vx * vx + vy * vy;
                let tproj = (((px - sx) * vx + (py - sy) * vy) / len2).clamp(0.0, 1.0);
                let (qx, qy) = (sx + tproj * vx, sy + tproj * vy);
                let shaft = ((px - qx).powi(2) + (py - qy).powi(2)).sqrt() <= s * 0.035;
                if ring || shaft {
                    rgba = [0x9e, 0xc1, 0xff, a];
                }
            }
            out.extend_from_slice(&rgba);
        }
    }
    out
}

/// ARGB32, network byte order, as the StatusNotifierItem specification wants.
#[allow(dead_code)]
pub fn argb(size: u32) -> Vec<u8> {
    rgba(size)
        .chunks(4)
        .flat_map(|p| [p[3], p[0], p[1], p[2]])
        .collect()
}
