// Response action confirmation (Phase 4 #74). Vanilla JS — the
// console is HTMX-first per ADR-0023, so any button needing a
// pre-submit guard advertises it via two data-attributes:
//
//   data-confirm="prompt"          single-click confirm via window.confirm
//   data-typed-confirm="phrase"    typed confirm — operator must type
//                                  the phrase exactly to release the
//                                  submit. Used for destructive
//                                  actions per ADR-0034.
//
// Listener attaches once on DOMContentLoaded; works for any future
// page that drops the data-attributes onto a <button> or <input
// type="submit">.

document.addEventListener('DOMContentLoaded', () => {
    document.body.addEventListener('click', (ev) => {
        const target = ev.target;
        if (!(target instanceof HTMLButtonElement) &&
            !(target instanceof HTMLInputElement && target.type === 'submit')) {
            return;
        }

        const typed = target.getAttribute('data-typed-confirm');
        if (typed) {
            const got = window.prompt(
                `This action is destructive.\nType "${typed}" to proceed:`);
            if (got !== typed) {
                ev.preventDefault();
                return;
            }
            return;
        }

        const confirmMsg = target.getAttribute('data-confirm');
        if (confirmMsg) {
            if (!window.confirm(confirmMsg)) {
                ev.preventDefault();
            }
        }
    });
});
