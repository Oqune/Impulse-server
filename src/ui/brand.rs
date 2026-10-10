//! Small colour adaptation of assets/brand/mark.svg; generated from identity V18.
//! No runtime image decoder or terminal graphics extension is required.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

const PIXELS: [[[u8; 3]; 6]; 6] = [
    [
        [6, 9, 15],
        [25, 39, 62],
        [26, 39, 60],
        [10, 18, 32],
        [5, 10, 20],
        [36, 40, 45],
    ],
    [
        [44, 66, 98],
        [67, 99, 144],
        [28, 46, 75],
        [32, 45, 67],
        [123, 129, 139],
        [49, 52, 60],
    ],
    [
        [95, 138, 192],
        [99, 138, 186],
        [107, 128, 157],
        [180, 191, 206],
        [80, 89, 108],
        [0, 6, 21],
    ],
    [
        [99, 142, 194],
        [127, 168, 221],
        [188, 211, 234],
        [126, 139, 164],
        [14, 23, 53],
        [19, 26, 42],
    ],
    [
        [59, 82, 109],
        [133, 175, 228],
        [133, 163, 207],
        [73, 87, 127],
        [40, 50, 79],
        [15, 22, 35],
    ],
    [
        [6, 9, 14],
        [59, 80, 105],
        [83, 110, 155],
        [61, 78, 117],
        [26, 34, 53],
        [7, 11, 16],
    ],
];

pub(super) fn draw_mark(frame: &mut Frame, area: Rect) {
    if area.width < 6 || area.height < 3 {
        return;
    }
    let lines = (0..3)
        .map(|y| {
            Line::from(
                (0..6)
                    .map(|x| {
                        let [r, g, b] = PIXELS[y * 2][x];
                        let [br, bg, bb] = PIXELS[y * 2 + 1][x];
                        Span::styled(
                            "▀",
                            Style::default()
                                .fg(Color::Rgb(r, g, b))
                                .bg(Color::Rgb(br, bg, bb)),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            width: 6,
            height: 3,
            ..area
        },
    );
}
