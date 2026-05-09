# Changelog

## 2026-05-09

- Added folder-level Quest mode for text-based photo requests.
- Added quest creation, quest comments, multiple photo uploads per quest, admin-only completion, and automatic return to shooting status when photos are added after completion.
- Added quest photo export support for PPT/PDF reports, including only completed quest photos while keeping the existing one-photo-per-slide layout.
- Added folder creation mode selection so folders are either photo folders or quest folders, preventing mixed photo/quest operation in a single folder.
- Changed report export to use the selected folder mode automatically instead of combining photo and quest content.
- Updated quest upload metadata placement so pending upload details appear inside the target quest card.
- Updated the Quest mode requirements document with the MVP behavior and folder mode constraints.
- Fixed a photo preview modal freeze caused by the translated `alt` attribute on the preview image being reset repeatedly by the i18n mutation observer.
