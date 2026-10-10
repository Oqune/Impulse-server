# Impulse identity V18

The graphite identity is shared by Client and Server. `mark.svg` is the editable transparent master; `icon.svg` is the graphite frame and `cobalt.svg` the alternate frame. PNGs are rendered from those sources. `geometry.json` records the pulse fit, congruent lenses and spherical envelope.

`readme-banner.svg/png` are the repository header (1200×360). `social-card.svg/png` are the GitHub social preview (1200×630); uploading a social preview is separate from committing a README. Text is outlined from the project's JetBrains Mono font so rendering does not depend on installed fonts.

Colour assets preserve the soft optical material. Android uses a 108 dp adaptive foreground at scale .75: all artwork fits inside the 66 dp safe circle. Its monochrome and splash VectorDrawables use the same exact pulse and conic contours, with simplified platform-native shading. The TUI uses a small colour sample of the master, without adding a raster runtime dependency.

Preserve the common centre/radius, 50° lens diagonal and -40° pulse axis. Do not tint the coloured master or stretch layers independently. UI dynamic colours remain separate from the brand's fixed optical material.

Source rules: https://developer.android.com/develop/ui/compose/system/icon_design_adaptive and https://developer.android.com/develop/ui/views/launch/splash-screen . Re-render colour exports from the SVG rather than tracing a PNG. Reproducible mathematical sources and platform exporters are included in the final design archive.

Native Android vectors use a compact C2 contour (36 segments, <0.05 source-unit boundary deviation). Full-colour SVG/PNG retain the exact master. Splash intrinsic size is 192 dp; the system controls its final drawing bounds.
