<?php

function safe_fixture_handler($value) {
    return esc_html((string) $value);
}
