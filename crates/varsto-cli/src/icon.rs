// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Procedurally drawn tray icon (no image decoder needed): the brand mark, a
//! blue tile with a broken ring around a keyhole. Returned as RGBA (Windows)
//! or ARGB big-endian (StatusNotifier).

pub fn rgba(size: u32) -> Vec<u8> {
    // The brand mark ("the dial", brand/render.py small tier): a blue rounded
    // tile, a white ring broken into two arcs, a keyhole in the middle.
    let s = size as f32;
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    let (cx, cy) = (s / 2.0, s / 2.0);
    let radius = s * 0.224;
    let inside_tile = |px: f32, py: f32| -> f32 {
        let h = s / 2.0 - 0.5;
        let dx = (px - cx).abs() - (h - radius);
        let dy = (py - cy).abs() - (h - radius);
        let outside =
            (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt() + dx.max(dy).min(0.0) - radius;
        -outside
    };
    // Ring geometry in fractions of the tile size; thicker strokes at small sizes.
    let ring_r = s * 0.33;
    let ring_w = if size <= 24 { s * 0.11 } else { s * 0.085 };
    let gap_half = if size <= 24 { 0.42f32 } else { 0.34 }; // radians, half width of each gap
    let gap_angles = [0.9f32, 0.9 + std::f32::consts::PI]; // upper-right and lower-left
    let hole_r = if size <= 24 { s * 0.11 } else { s * 0.095 };
    let hole_c = (cx, cy - s * 0.06);
    let stem_w = if size <= 24 { s * 0.11 } else { s * 0.085 };
    let stem_bottom = cy + s * 0.2;
    let coverage = |d: f32| -> f32 { (d + 0.5).clamp(0.0, 1.0) };
    for y in 0..size {
        for x in 0..size {
            let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
            let d = inside_tile(px, py);
            let mut rgba = [0u8, 0, 0, 0];
            if d > -1.0 {
                let a = ((d + 1.0).clamp(0.0, 1.0) * 255.0) as u8;
                rgba = [0x2b, 0x57, 0xd6, a];
                // Ring with two gaps.
                let (vx, vy) = (px - cx, py - cy);
                let dist = (vx * vx + vy * vy).sqrt();
                let ang = vy.atan2(vx);
                let in_gap = gap_angles.iter().any(|g| {
                    let mut diff = (ang - g).abs();
                    while diff > std::f32::consts::PI {
                        diff = (diff - 2.0 * std::f32::consts::PI).abs();
                    }
                    diff < gap_half
                });
                let ring_d = ring_w / 2.0 - (dist - ring_r).abs();
                let mut white = if in_gap { 0.0 } else { coverage(ring_d) };
                // Keyhole: a circle and a stem below it.
                let hd = hole_r - ((px - hole_c.0).powi(2) + (py - hole_c.1).powi(2)).sqrt();
                white = white.max(coverage(hd));
                if py >= hole_c.1 && py <= stem_bottom {
                    let sd = stem_w / 2.0 - (px - cx).abs();
                    let bd = stem_bottom - py;
                    white = white.max(coverage(sd.min(bd)));
                }
                if white > 0.0 {
                    let mix = |c: u8| -> u8 { (c as f32 + (255.0 - c as f32) * white) as u8 };
                    rgba = [mix(0x2b), mix(0x57), mix(0xd6), a];
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

#[cfg(test)]
mod tests {
    #[test]
    fn icon_renders_as_tile_with_white_mark() {
        for size in [16u32, 22, 32, 64] {
            let px = super::rgba(size);
            assert_eq!(px.len(), (size * size * 4) as usize);
            let white = px
                .chunks(4)
                .filter(|p| p[0] > 200 && p[1] > 200 && p[2] > 200 && p[3] > 0)
                .count();
            let blue = px
                .chunks(4)
                .filter(|p| p[2] > 150 && p[0] < 100 && p[3] > 0)
                .count();
            assert!(
                white > (size * size / 12) as usize,
                "size {size}: too little white ({white})"
            );
            assert!(
                blue > (size * size / 3) as usize,
                "size {size}: too little blue ({blue})"
            );
        }
        // A small ASCII rendering for eyeballing with --nocapture.
        let size = 22;
        let px = super::rgba(size);
        for y in 0..size {
            let row: String = (0..size)
                .map(|x| {
                    let p = &px[((y * size + x) * 4) as usize..][..4];
                    if p[3] == 0 {
                        ' '
                    } else if p[0] > 200 {
                        '#'
                    } else {
                        '.'
                    }
                })
                .collect();
            println!("{row}");
        }
    }
}
