//! fetch>it desktop binary entry point. The actual app lives in the
//! library crate (`fetchit_desktop_lib`); this is just a thin trampoline.

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    fetchit_desktop_lib::run();
}
