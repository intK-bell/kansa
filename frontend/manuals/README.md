# Manuals

## Current In-App Manual
- `kansa-manual.html` is the current in-app manual linked from the help modal.
- It uses `../i18n.js` and `data-i18n` keys so the content follows the app language.
- `kansa-manual.pdf` is retained as a legacy/reference file.

## Maintained Text Sources
- Japanese: `docs/user-guide.md`
- English: `docs/user-guide.en.md`
- Chinese: `docs/user-guide.zh-CN.md`
- Vietnamese: `docs/user-guide.vi.md`

## Maintenance
Update `kansa-manual.html` and the matching keys in `frontend/i18n.js` when manual wording changes. If the PDF is regenerated later, treat it as a derived artifact and keep the HTML/manual text as the editable source.
