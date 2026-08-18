<?php
/*
 * Minimal vulnerable handler (Fig. 1 of the paper).
 * One five-line function carries three distinct issues that WISP reports:
 *   - XSS:  $_POST['note'] flows unescaped into echo
 *   - CSRF: a state change (update_option) with no wp_verify_nonce
 *   - broken access control: no current_user_can check
 * All three are tagged with the unauthenticated entry point ajax_nopriv.
 * A generic analyzer sees at most the echo; the hook registration and the
 * missing guards are WordPress semantics.
 */

add_action('wp_ajax_nopriv_save_note', 'save_note');

function save_note() {
    $note = $_POST['note'];          // source: unauthenticated AJAX input
    update_option('note', $note);    // state change, no nonce / capability guard
    echo 'Saved: ' . $note;          // sink: unescaped output (XSS)
}
