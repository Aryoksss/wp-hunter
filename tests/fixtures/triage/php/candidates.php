<?php

function triage_fixture_handler() {
    $path = $_GET['path'];
    $payload = $_POST['payload'];
    file_put_contents($path, $payload);
    $wpdb->query("SELECT * FROM {$wpdb->users}");
    update_user_meta($_POST['user_id'], 'role', $_POST['role']);
    eval($_POST['code']);
    echo $_GET['name'];
}

add_action('wp_ajax_nopriv_fixture', 'triage_fixture_handler');
register_rest_route('fixture/v1', '/item', array(
    'permission_callback' => '__return_true',
));
