use std::cell::Cell;
use std::f64::consts::PI;
use std::rc::Rc;

use gtk::prelude::*;
use gtk::{gdk, glib};
use openhello_gui_core::{CaptureUpdate, Strings, Text};

use crate::geometry;

const GUIDE_ALPHA: f64 = 0.85;
const TRACK_ALPHA: f64 = 0.3;
const GUIDE_WIDTH: f64 = 2.5;
const RING_WIDTH: f64 = 6.0;
const MICROS: f64 = 1_000_000.0;

#[derive(Default)]
struct Ring {
    target: Cell<f64>,
    shown: Cell<f64>,
    required: Cell<u32>,
    last_frame_time: Cell<i64>,
}

pub struct CaptureView {
    root: gtk::Box,
    picture: gtk::Picture,
    frame: gtk::Overlay,
    canvas: gtk::DrawingArea,
    guidance: gtk::Label,
    progress: gtk::Label,
    ring: Rc<Ring>,
}

impl CaptureView {
    pub fn new(strings: &Strings, on_cancel: impl Fn() + 'static) -> Self {
        let picture = gtk::Picture::builder().content_fit(gtk::ContentFit::Cover).can_shrink(true).overflow(gtk::Overflow::Hidden).build();
        let canvas = gtk::DrawingArea::builder().css_classes(["ring"]).build();
        let frame = preview_frame(&picture, &canvas);
        let guidance = gtk::Label::builder().wrap(true).justify(gtk::Justification::Center).css_classes(["title-3"]).build();
        let progress = gtk::Label::builder().css_classes(["dim-label", "numeric"]).build();
        let cancel = gtk::Button::builder().label(strings.get(Text::Cancel)).halign(gtk::Align::Center).css_classes(["pill"]).build();
        cancel.connect_clicked(move |_| on_cancel());
        let root = column(&[frame.upcast_ref(), guidance.upcast_ref(), progress.upcast_ref(), cancel.upcast_ref()]);
        let ring = Rc::new(Ring::default());
        install_drawing(&canvas, &ring);
        install_animation(&canvas, &ring);
        let view = Self { root, picture, frame, canvas, guidance, progress, ring };
        view.reset(strings);
        view
    }

    pub fn widget(&self) -> &gtk::Widget {
        self.root.upcast_ref()
    }

    pub fn reset(&self, strings: &Strings) {
        self.picture.set_paintable(None::<&gdk::Paintable>);
        self.guidance.set_label(strings.get(Text::CaptureTitle));
        self.progress.set_label("");
        self.ring.target.set(0.0);
        self.ring.shown.set(0.0);
        self.ring.last_frame_time.set(0);
        self.canvas.queue_draw();
    }

    pub fn update(&self, update: &CaptureUpdate) {
        self.guidance.set_label(update.guidance);
        self.progress.set_label(&update.progress_text);
        self.ring.required.set(update.required);
        self.ring.target.set(geometry::fraction(update.filled, update.required));
        if let Some(frame) = &update.frame {
            self.show_frame(frame.width, frame.height, &frame.pixels);
        }
    }

    fn show_frame(&self, width: u32, height: u32, gray: &[u8]) {
        let Some(rgba) = geometry::mirrored_rgba(width, height, gray) else { return };
        let (Ok(columns), Ok(rows)) = (i32::try_from(width), i32::try_from(height)) else { return };
        let texture = gdk::MemoryTexture::new(columns, rows, gdk::MemoryFormat::R8g8b8a8Premultiplied, &glib::Bytes::from_owned(rgba), width as usize * 4);
        self.picture.set_paintable(Some(&texture));
        let (preview_width, preview_height) = geometry::preview_size(width, height);
        self.frame.set_size_request(preview_width, preview_height);
    }
}

fn preview_frame(picture: &gtk::Picture, canvas: &gtk::DrawingArea) -> gtk::Overlay {
    let frame = gtk::Overlay::builder().child(picture).halign(gtk::Align::Center).overflow(gtk::Overflow::Hidden).css_classes(["preview-frame"]).build();
    let (width, height) = geometry::preview_size(0, 0);
    frame.set_size_request(width, height);
    frame.add_overlay(canvas);
    frame
}

fn column(children: &[&gtk::Widget]) -> gtk::Box {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .valign(gtk::Align::Center)
        .build();
    for child in children {
        root.append(*child);
    }
    root
}

fn install_drawing(canvas: &gtk::DrawingArea, ring: &Rc<Ring>) {
    let ring = Rc::clone(ring);
    canvas.set_draw_func(move |area, cr, width, height| {
        let accent = area.color();
        let (width, height) = (f64::from(width), f64::from(height));
        stroke_oval(cr, geometry::guide_oval(width, height), GUIDE_WIDTH, (1.0, 1.0, 1.0, GUIDE_ALPHA), 0.0, 2.0 * PI);
        draw_ring(cr, geometry::ring_oval(width, height), &ring, (accent.red().into(), accent.green().into(), accent.blue().into()));
    });
}

fn draw_ring(cr: &gtk::cairo::Context, oval: geometry::Oval, ring: &Ring, accent: (f64, f64, f64)) {
    let required = ring.required.get();
    for (index, (start, end)) in geometry::segments(required).into_iter().enumerate() {
        stroke_oval(cr, oval, RING_WIDTH, (1.0, 1.0, 1.0, TRACK_ALPHA), start, end);
        let fill = geometry::segment_fill(ring.shown.get(), required, index as u32);
        if fill > 0.0 {
            stroke_oval(cr, oval, RING_WIDTH, (accent.0, accent.1, accent.2, 1.0), start, start + (end - start) * fill);
        }
    }
}

fn stroke_oval(cr: &gtk::cairo::Context, oval: geometry::Oval, width: f64, color: (f64, f64, f64, f64), start: f64, end: f64) {
    cr.save().ok();
    cr.translate(oval.cx, oval.cy);
    cr.scale(oval.rx, oval.ry);
    cr.new_path();
    cr.arc(0.0, 0.0, 1.0, start, end);
    cr.restore().ok();
    cr.set_source_rgba(color.0, color.1, color.2, color.3);
    cr.set_line_width(width);
    cr.set_line_cap(gtk::cairo::LineCap::Round);
    cr.stroke().ok();
}

fn install_animation(canvas: &gtk::DrawingArea, ring: &Rc<Ring>) {
    let ring = Rc::clone(ring);
    canvas.add_tick_callback(move |area, clock| {
        let now = clock.frame_time();
        let seconds = match ring.last_frame_time.replace(now) {
            0 => 0.0,
            previous => (now - previous) as f64 / MICROS,
        };
        let (shown, target) = (ring.shown.get(), ring.target.get());
        if shown != target {
            let animated = area.settings().is_gtk_enable_animations();
            ring.shown.set(if animated { geometry::ease_toward(shown, target, seconds) } else { target });
            area.queue_draw();
        }
        glib::ControlFlow::Continue
    });
}
