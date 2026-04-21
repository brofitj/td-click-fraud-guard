<?php
/**
 * Plugin Name: TD - Click Fraud Guard
 * Plugin URI: https://tebardigital.co.id
 * Description: Mencatat dan menandai aktivitas klik yang terindikasi tidak valid, dengan opsi pemblokiran dan aturan geolokasi.
 * Version: 1.0.0
 * Author: TebarDigital
 * Author URI: https://tebardigital.co.id
 * License: GPL2
 */

if (!defined('ABSPATH')) {
    exit;
}

class CFG_Click_Fraud_Guard {
    const OPTION_KEY = 'cfg_settings';
    const CRON_HOOK = 'cfg_cleanup_logs';

    public static function init() {
        register_activation_hook(__FILE__, array(__CLASS__, 'activate'));
        register_deactivation_hook(__FILE__, array(__CLASS__, 'deactivate'));

        add_action('init', array(__CLASS__, 'maybe_log_click'), 20);
        add_action('admin_menu', array(__CLASS__, 'admin_menu'));
        add_action('admin_init', array(__CLASS__, 'register_settings'));
        add_action('admin_init', array(__CLASS__, 'ensure_list_table'));
        add_action('current_screen', array(__CLASS__, 'add_logs_help_tabs'));
        add_action('wp_enqueue_scripts', array(__CLASS__, 'enqueue_front_assets'));
        add_action('wp_ajax_cfg_log_click', array(__CLASS__, 'handle_js_log'));
        add_action('wp_ajax_nopriv_cfg_log_click', array(__CLASS__, 'handle_js_log'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'enqueue_admin_assets'));
        add_action('admin_post_cfg_toggle_excluded', array(__CLASS__, 'handle_toggle_excluded'));
        add_action(self::CRON_HOOK, array(__CLASS__, 'cleanup_logs'));
    }

    public static function activate() {
        self::create_table();
        self::create_exclusions_table();
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
        }
    }

    public static function deactivate() {
        $timestamp = wp_next_scheduled(self::CRON_HOOK);
        if ($timestamp) {
            wp_unschedule_event($timestamp, self::CRON_HOOK);
        }
    }

    private static function defaults() {
        return array(
            'repeat_window_minutes' => 5,
            'repeat_threshold' => 2,
            'blocked_countries' => '',
            'allowed_countries' => '',
            'use_cf_header' => 1,
            'retention_days' => 30,
        );
    }

    public static function get_settings() {
        $settings = get_option(self::OPTION_KEY, array());
        return wp_parse_args($settings, self::defaults());
    }

    public static function create_table() {
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            ip VARCHAR(45) NOT NULL,
            user_agent TEXT NULL,
            referrer TEXT NULL,
            gclid VARCHAR(200) NULL,
            landing_url TEXT NULL,
            country CHAR(2) NULL,
            is_flagged TINYINT(1) NOT NULL DEFAULT 0,
            flag_reason TEXT NULL,
            visit_count BIGINT UNSIGNED NOT NULL DEFAULT 1,
            is_excluded TINYINT(1) NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            KEY idx_ip_created (ip, created_at),
            KEY idx_created (created_at),
            KEY idx_gclid (gclid)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public static function create_exclusions_table() {
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_excluded_ips';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            ip VARCHAR(45) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY  (ip)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public static function maybe_log_click() {
        // Logging now handled via JS ping to keep page cache effective.
        return;
    }

    public static function enqueue_front_assets() {
        if (is_admin()) {
            return;
        }
        $base = plugin_dir_url(__FILE__);
        wp_enqueue_script('cfg-front', $base . 'assets/cfg-front.js', array(), '1.0.0', true);
        wp_localize_script('cfg-front', 'CFG_LOG', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('cfg_log_click'),
        ));
    }

    public static function handle_js_log() {
        $nonce = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';
        if (!empty($nonce) && !wp_verify_nonce($nonce, 'cfg_log_click')) {
            wp_send_json_error('invalid_nonce', 403);
        }

        if (is_user_logged_in() && current_user_can('manage_options')) {
            wp_send_json_success('skipped_admin');
        }

        $gclid = isset($_POST['gclid']) ? sanitize_text_field(wp_unslash($_POST['gclid'])) : '';
        if ($gclid === '') {
            wp_send_json_error('missing_gclid', 400);
        }

        $settings = self::get_settings();
        $ip = self::get_ip();
        if (empty($ip)) {
            wp_send_json_error('missing_ip', 400);
        }

        $country = self::get_country($settings);
        $reasons = array();
        if (!empty($country)) {
            $blocked = self::parse_country_list($settings['blocked_countries']);
            if (!empty($blocked) && in_array($country, $blocked, true)) {
                $reasons[] = 'blocked_country';
            }

            $allowed = self::parse_country_list($settings['allowed_countries']);
            if (!empty($allowed) && !in_array($country, $allowed, true)) {
                $reasons[] = 'not_allowed_country';
            }
        }

        $is_flagged = !empty($reasons);
        $now_gmt = current_time('mysql', true);
        $data = array(
            'created_at' => $now_gmt,
            'last_seen' => $now_gmt,
            'ip' => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? wp_unslash($_SERVER['HTTP_USER_AGENT']) : '',
            'referrer' => isset($_POST['referrer']) ? wp_unslash($_POST['referrer']) : '',
            'gclid' => $gclid,
            'landing_url' => isset($_POST['url']) ? esc_url_raw(wp_unslash($_POST['url'])) : '',
            'country' => $country,
            'is_flagged' => $is_flagged ? 1 : 0,
            'flag_reason' => $is_flagged ? implode(',', $reasons) : '',
            'visit_count' => 1,
            'is_excluded' => 0,
        );

        self::upsert_log($data, $settings);
        wp_send_json_success('logged');
    }

    private static function insert_log($data) {
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $wpdb->insert($table, $data, array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%d'));
    }

    private static function upsert_log($data, $settings) {
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';

        $window_minutes = max(1, (int)$settings['repeat_window_minutes']);
        $since = gmdate('Y-m-d H:i:s', time() - ($window_minutes * 60));
        $existing = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT id, visit_count FROM {$table} WHERE ip = %s AND gclid = %s AND created_at >= %s ORDER BY created_at DESC LIMIT 1",
                $data['ip'],
                $data['gclid'],
                $since
            )
        );

        if ($existing) {
            $wpdb->update(
                $table,
                array(
                    'last_seen' => $data['last_seen'],
                    'visit_count' => (int)$existing->visit_count + 1,
                    'gclid' => $data['gclid'],
                    'landing_url' => $data['landing_url'],
                    'country' => $data['country'],
                    'is_flagged' => $data['is_flagged'],
                    'flag_reason' => $data['flag_reason'],
                ),
                array('id' => (int)$existing->id),
                array('%s', '%d', '%s', '%s', '%s', '%d', '%s'),
                array('%d')
            );
            return;
        }

        self::insert_log($data);
    }

    private static function is_repeat_click($ip, $gclid, $window_minutes, $threshold) {
        $window_minutes = max(1, (int)$window_minutes);
        $threshold = max(2, (int)$threshold);
        $window_seconds = $window_minutes * 60;
        $now = time();
        $key = 'cfg_repeat_' . md5($ip . '|' . (string)$gclid);
        $timestamps = get_transient($key);
        if (!is_array($timestamps)) {
            $timestamps = array();
        }
        $cutoff = $now - $window_seconds;
        $timestamps = array_values(array_filter($timestamps, function ($ts) use ($cutoff) {
            return $ts >= $cutoff;
        }));
        if (!empty($timestamps)) {
            $last = end($timestamps);
            if (($now - $last) < 2) {
                set_transient($key, $timestamps, $window_seconds + 30);
                return false;
            }
        }
        $timestamps[] = $now;
        set_transient($key, $timestamps, $window_seconds + 30);
        return count($timestamps) >= $threshold;
    }

    private static function parse_country_list($list) {
        if (empty($list)) {
            return array();
        }
        $parts = preg_split('/[\s,]+/', strtoupper($list));
        $parts = array_filter(array_map('sanitize_text_field', $parts));
        $parts = array_filter($parts, function ($code) {
            return strlen($code) === 2;
        });
        return array_values(array_unique($parts));
    }

    private static function get_ip() {
        $keys = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR',
        );
        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
                $value = wp_unslash($_SERVER[$key]);
                if ($key === 'HTTP_X_FORWARDED_FOR') {
                    $parts = explode(',', $value);
                    $value = trim($parts[0]);
                }
                $value = trim($value);
                if (filter_var($value, FILTER_VALIDATE_IP)) {
                    return $value;
                }
            }
        }
        return '';
    }

    private static function get_country($settings) {
        if ((int)$settings['use_cf_header'] !== 1) {
            return '';
        }
        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $country = strtoupper(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY'])));
            if (strlen($country) === 2) {
                return $country;
            }
        }
        return '';
    }

    private static function current_url() {
        $scheme = is_ssl() ? 'https' : 'http';
        $host = isset($_SERVER['HTTP_HOST']) ? wp_unslash($_SERVER['HTTP_HOST']) : '';
        $uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        return esc_url_raw($scheme . '://' . $host . $uri);
    }

    public static function format_wib($mysql_utc) {
        if (empty($mysql_utc)) {
            return '';
        }
        $dt = date_create($mysql_utc, new DateTimeZone('UTC'));
        if (!$dt) {
            return $mysql_utc;
        }
        $dt->setTimezone(new DateTimeZone('Asia/Jakarta'));
        return $dt->format('Y-m-d H:i:s');
    }

    public static function admin_menu() {
        add_menu_page(
            'Click Fraud Guard Settings',
            'Click Fraud Guard',
            'manage_options',
            'click-fraud-guard',
            array(__CLASS__, 'render_settings_page'),
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'click-fraud-guard',
            'Click Fraud Guard Logs',
            'Logs',
            'manage_options',
            'click-fraud-guard-logs',
            array(__CLASS__, 'render_logs_page')
        );

        // Rename the auto-added first submenu label to "Settings" for clarity.
        global $submenu;
        if (isset($submenu['click-fraud-guard'][0][0])) {
            $submenu['click-fraud-guard'][0][0] = 'Settings';
        }
        // Move Logs above Settings.
        if (isset($submenu['click-fraud-guard'][0], $submenu['click-fraud-guard'][1])) {
            $logs = $submenu['click-fraud-guard'][1];
            $settings = $submenu['click-fraud-guard'][0];
            $submenu['click-fraud-guard'][0] = $logs;
            $submenu['click-fraud-guard'][1] = $settings;
        }
    }

    public static function register_settings() {
        register_setting('cfg_settings_group', self::OPTION_KEY, array(__CLASS__, 'sanitize_settings'));
    }

    public static function ensure_list_table() {
        if (!class_exists('WP_List_Table')) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
        }
    }

    public static function sanitize_settings($input) {
        $defaults = self::defaults();
        $output = array();

        $output['repeat_window_minutes'] = isset($input['repeat_window_minutes']) ? max(1, (int)$input['repeat_window_minutes']) : $defaults['repeat_window_minutes'];
        $output['repeat_threshold'] = isset($input['repeat_threshold']) ? max(2, (int)$input['repeat_threshold']) : $defaults['repeat_threshold'];
        $output['blocked_countries'] = isset($input['blocked_countries']) ? sanitize_text_field($input['blocked_countries']) : '';
        $output['allowed_countries'] = isset($input['allowed_countries']) ? sanitize_text_field($input['allowed_countries']) : '';
        $output['use_cf_header'] = isset($input['use_cf_header']) ? 1 : 0;
        $output['retention_days'] = isset($input['retention_days']) ? max(1, (int)$input['retention_days']) : $defaults['retention_days'];

        return $output;
    }

    public static function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $settings = self::get_settings();
        ?>
        <div class="wrap">
            <h1>Click Fraud Guard Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields('cfg_settings_group'); ?>
            <h2>Repeat Click Rule</h2>
            <table class="form-table">
                <tr>
                    <th scope="row">Window (minutes)</th>
                        <td><input type="number" min="1" name="<?php echo esc_attr(self::OPTION_KEY); ?>[repeat_window_minutes]" value="<?php echo esc_attr($settings['repeat_window_minutes']); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Threshold (clicks)</th>
                        <td><input type="number" min="2" name="<?php echo esc_attr(self::OPTION_KEY); ?>[repeat_threshold]" value="<?php echo esc_attr($settings['repeat_threshold']); ?>" /></td>
                    </tr>
                </table>

                <h2>Geo Rules</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">Use Cloudflare country header</th>
                        <td><label><input type="checkbox" name="<?php echo esc_attr(self::OPTION_KEY); ?>[use_cf_header]" <?php checked($settings['use_cf_header'], 1); ?> /> Use CF-IPCountry header</label></td>
                    </tr>
                    <tr>
                        <th scope="row">Blocked countries</th>
                        <td><input type="text" class="regular-text" name="<?php echo esc_attr(self::OPTION_KEY); ?>[blocked_countries]" value="<?php echo esc_attr($settings['blocked_countries']); ?>" placeholder="CN RU" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Allowed countries (optional)</th>
                        <td><input type="text" class="regular-text" name="<?php echo esc_attr(self::OPTION_KEY); ?>[allowed_countries]" value="<?php echo esc_attr($settings['allowed_countries']); ?>" placeholder="ID SG" /></td>
                    </tr>
                </table>

            <h2>Data Retention</h2>
            <table class="form-table">
                <tr>
                    <th scope="row">Retention (days)</th>
                        <td><input type="number" min="1" name="<?php echo esc_attr(self::OPTION_KEY); ?>[retention_days]" value="<?php echo esc_attr($settings['retention_days']); ?>" /></td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    public static function render_logs_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        self::ensure_list_table();
        $table = new CFG_Click_Log_Table();
        $table->process_bulk_action();
        $table->prepare_items();
        $toggled = isset($_GET['cfg_excluded_updated']) ? (int)$_GET['cfg_excluded_updated'] : 0;
        ?>
        <div class="wrap">
            <h1 class="cfg-page-title">Click Fraud Guard Logs <button type="button" class="cfg-help-toggle button-link" aria-label="Help"><span class="dashicons dashicons-editor-help" aria-hidden="true"></span></button></h1>
            <?php if ($toggled) : ?>
                <div class="notice notice-success is-dismissible">
                    <p>Status exclude berhasil diperbarui.</p>
                </div>
            <?php endif; ?>
            <?php if ($table->deleted_count > 0) : ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php echo esc_html($table->deleted_count); ?> log berhasil dihapus.</p>
                </div>
            <?php endif; ?>
            <form method="post">
                <input type="hidden" name="page" value="click-fraud-guard-logs" />
                <?php $table->views(); ?>
                <?php $table->display(); ?>
            </form>
        </div>
        <?php
    }

    public static function add_logs_help_tabs() {
        if (!function_exists('get_current_screen')) {
            return;
        }
        $screen = get_current_screen();
        if (!$screen || (strpos($screen->id, 'click-fraud-guard-logs') === false)) {
            return;
        }
        $screen->add_help_tab(array(
            'id' => 'cfg_logs_help_overview',
            'title' => 'Cara Kerja Log',
            'content' => '<p>Halaman ini menyimpan jejak kunjungan berdasarkan IP dan GCLID. Setiap request dicatat sebagai log, dan jika IP + GCLID yang sama terjadi dalam window waktu yang sama, data akan diupdate (bukan menambah baris).</p>'
                . '<p>Kolom <strong>Visits</strong> menunjukkan jumlah kunjungan dalam window. Jika melebihi Threshold, akan muncul bendera merah sebagai indikator.</p>'
                . '<p>Status <strong>Excluded</strong> disimpan per IP (bukan per log) agar mudah menandai IP yang sudah Anda exclude di Google Ads.</p>',
        ));
        $screen->add_help_tab(array(
            'id' => 'cfg_logs_help_timezone',
            'title' => 'Zona Waktu',
            'content' => '<p>Zona waktu yang digunakan adalah <strong>WIB (Asia/Jakarta)</strong>.</p>',
        ));
        $screen->add_help_tab(array(
            'id' => 'cfg_logs_help_js',
            'title' => 'Logging via JS',
            'content' => '<p>Logging dilakukan melalui JavaScript agar halaman tetap dapat di-cache. Saat URL mengandung <code>gclid</code>, browser akan mengirim ping ke server untuk menambah log.</p>'
                . '<p>Jika JavaScript diblokir atau request ke <code>admin-ajax.php</code> dibatasi, log bisa tidak tercatat.</p>',
        ));
        $screen->set_help_sidebar('<p><strong>Butuh bantuan?</strong></p><p>Periksa pengaturan Threshold dan Window untuk menyesuaikan indikator bendera merah.</p>');
    }

    public static function enqueue_admin_assets($hook) {
        if (strpos($hook, 'click-fraud-guard-logs') === false) {
            return;
        }
        $base = plugin_dir_url(__FILE__);
        wp_enqueue_style('cfg-logs', $base . 'assets/cfg-logs.css', array(), '1.0.0');
        wp_enqueue_script('cfg-logs', $base . 'assets/cfg-logs.js', array(), '1.0.0', true);
    }

    public static function handle_delete_logs() {
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized', 403);
        }
        check_admin_referer('cfg_delete_logs');
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $wpdb->query("TRUNCATE TABLE {$table}");
        wp_safe_redirect(admin_url('admin.php?page=click-fraud-guard-logs'));
        exit;
    }

    public static function get_logs($per_page, $offset, $excluded_filter = 'all', $flag_filter = 'all', $threshold = 0) {
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $ex_table = $wpdb->prefix . 'cfg_excluded_ips';
        $per_page = max(1, (int)$per_page);
        $offset = max(0, (int)$offset);
        $where = array();
        if ($excluded_filter === 'excluded') {
            $where[] = "ip IN (SELECT ip FROM {$ex_table})";
        } elseif ($excluded_filter === 'not_excluded') {
            $where[] = "ip NOT IN (SELECT ip FROM {$ex_table})";
        }
        if ($flag_filter === 'flagged' && $threshold > 0) {
            $where[] = $wpdb->prepare("visit_count > %d", (int)$threshold);
        } elseif ($flag_filter === 'not_flagged' && $threshold > 0) {
            $where[] = $wpdb->prepare("visit_count <= %d", (int)$threshold);
        }
        $where_sql = '';
        if (!empty($where)) {
            $where_sql = 'WHERE ' . implode(' AND ', $where);
        }
        $sql = "SELECT * FROM {$table} {$where_sql} ORDER BY created_at DESC LIMIT %d OFFSET %d";
        return $wpdb->get_results($wpdb->prepare($sql, $per_page, $offset));
    }

    public static function get_logs_count($excluded_filter = 'all', $flag_filter = 'all', $threshold = 0) {
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $ex_table = $wpdb->prefix . 'cfg_excluded_ips';
        $where = array();
        if ($excluded_filter === 'excluded') {
            $where[] = "ip IN (SELECT ip FROM {$ex_table})";
        } elseif ($excluded_filter === 'not_excluded') {
            $where[] = "ip NOT IN (SELECT ip FROM {$ex_table})";
        }
        if ($flag_filter === 'flagged' && $threshold > 0) {
            $where[] = $wpdb->prepare("visit_count > %d", (int)$threshold);
        } elseif ($flag_filter === 'not_flagged' && $threshold > 0) {
            $where[] = $wpdb->prepare("visit_count <= %d", (int)$threshold);
        }
        $where_sql = '';
        if (!empty($where)) {
            $where_sql = 'WHERE ' . implode(' AND ', $where);
        }
        return (int)$wpdb->get_var("SELECT COUNT(*) FROM {$table} {$where_sql}");
    }

    public static function delete_logs_by_ids($ids) {
        $ids = array_filter(array_map('absint', (array)$ids));
        if (empty($ids)) {
            return 0;
        }
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $placeholders = implode(',', array_fill(0, count($ids), '%d'));
        $sql = $wpdb->prepare("DELETE FROM {$table} WHERE id IN ($placeholders)", $ids);
        $wpdb->query($sql);
        return $wpdb->rows_affected;
    }

    public static function update_excluded_status($ip, $is_excluded) {
        $ip = trim((string)$ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_excluded_ips';
        $now = current_time('mysql', true);
        if ($is_excluded) {
            $wpdb->replace(
                $table,
                array(
                    'ip' => $ip,
                    'created_at' => $now,
                    'updated_at' => $now,
                ),
                array('%s', '%s', '%s')
            );
        } else {
            $wpdb->delete($table, array('ip' => $ip), array('%s'));
        }
    }

    public static function handle_toggle_excluded() {
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized', 403);
        }
        $ip = isset($_GET['ip']) ? sanitize_text_field(wp_unslash($_GET['ip'])) : '';
        $new = isset($_GET['new']) ? absint($_GET['new']) : 0;
        check_admin_referer('cfg_toggle_excluded_' . md5($ip));
        self::update_excluded_status($ip, $new === 1);
        wp_safe_redirect(admin_url('admin.php?page=click-fraud-guard-logs&cfg_excluded_updated=1'));
        exit;
    }

    public static function get_excluded_map($ips) {
        $ips = array_filter(array_map('trim', (array)$ips));
        $ips = array_filter($ips, function ($ip) {
            return filter_var($ip, FILTER_VALIDATE_IP);
        });
        if (empty($ips)) {
            return array();
        }
        global $wpdb;
        $table = $wpdb->prefix . 'cfg_excluded_ips';
        $placeholders = implode(',', array_fill(0, count($ips), '%s'));
        $sql = $wpdb->prepare("SELECT ip FROM {$table} WHERE ip IN ($placeholders)", $ips);
        $rows = $wpdb->get_col($sql);
        $map = array();
        foreach ($rows as $ip) {
            $map[$ip] = true;
        }
        return $map;
    }

    public static function cleanup_logs() {
        $settings = self::get_settings();
        $days = max(1, (int)$settings['retention_days']);
        $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * 86400));

        global $wpdb;
        $table = $wpdb->prefix . 'cfg_clicks';
        $wpdb->query(
            $wpdb->prepare("DELETE FROM {$table} WHERE created_at < %s", $cutoff)
        );
    }
}

if (is_admin()) {
    if (!class_exists('WP_List_Table')) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
    }
    
    class CFG_Click_Log_Table extends WP_List_Table {
        public $deleted_count = 0;
        public $excluded_map = array();
        public $excluded_filter = 'all';
        public $repeat_threshold = 0;
        public $flag_filter = 'all';

        public function __construct() {
            parent::__construct(array(
                'singular' => 'log',
                'plural' => 'logs',
                'ajax' => false,
            ));
        }

        public function get_columns() {
            return array(
                'cb' => '<input type="checkbox" />',
                'created_at' => 'Time',
                'last_seen' => 'Last Seen',
                'ip' => 'IP',
                'visit_count' => 'Visits',
                'country' => 'Country',
                'gclid' => 'GCLID',
                'landing_url' => 'URL',
                'is_excluded' => 'Status',
                'exclude_action' => 'Action',
            );
        }

        protected function get_bulk_actions() {
            return array(
                'delete' => 'Hapus',
            );
        }

        protected function column_cb($item) {
            return sprintf('<input type="checkbox" name="log_id[]" value="%d" />', (int)$item->id);
        }

        public function column_default($item, $column_name) {
            switch ($column_name) {
                case 'created_at':
                    return esc_html(CFG_Click_Fraud_Guard::format_wib($item->created_at));
                case 'last_seen':
                    return esc_html(CFG_Click_Fraud_Guard::format_wib($item->last_seen));
                case 'ip':
                    return esc_html($item->ip) . ' <button type="button" class="button button-small cfg-copy-ip" data-ip="' . esc_attr($item->ip) . '" aria-label="Copy IP"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span></button>';
                case 'visit_count':
                    $count = (int)$item->visit_count;
                    $flag = $count > $this->repeat_threshold ? '<span class="cfg-flag">⚑</span>' : '';
                    return esc_html($count) . $flag;
                case 'landing_url':
                    return '<code>' . esc_html($item->landing_url) . '</code>';
                case 'is_excluded':
                    $is_excluded = isset($this->excluded_map[$item->ip]) && $this->excluded_map[$item->ip];
                    $label = $is_excluded ? 'Excluded' : 'Not Excluded';
                    $label_class = $is_excluded ? 'cfg-label cfg-label-red' : 'cfg-label cfg-label-green';
                    return '<span class="' . esc_attr($label_class) . '">' . esc_html($label) . '</span>';
                case 'exclude_action':
                    $is_excluded = isset($this->excluded_map[$item->ip]) && $this->excluded_map[$item->ip];
                    $toggle = $is_excluded ? 0 : 1;
                    $action_label = $is_excluded ? 'Unmark' : 'Mark';
                    $url = add_query_arg(
                        array(
                            'action' => 'cfg_toggle_excluded',
                            'ip' => $item->ip,
                            'new' => $toggle,
                        ),
                        admin_url('admin-post.php')
                    );
                    $url = wp_nonce_url($url, 'cfg_toggle_excluded_' . md5($item->ip));
                    return '<a class="button button-small" href="' . esc_url($url) . '">' . esc_html($action_label) . '</a>';
                default:
                    return esc_html($item->$column_name);
            }
        }

        public function prepare_items() {
            $per_page = 10;
            $current_page = $this->get_pagenum();
            $this->excluded_filter = isset($_GET['excluded']) ? sanitize_text_field(wp_unslash($_GET['excluded'])) : 'all';
            if (!in_array($this->excluded_filter, array('all', 'excluded', 'not_excluded'), true)) {
                $this->excluded_filter = 'all';
            }
            $this->flag_filter = isset($_GET['flagged']) ? sanitize_text_field(wp_unslash($_GET['flagged'])) : 'all';
            if (!in_array($this->flag_filter, array('all', 'flagged', 'not_flagged'), true)) {
                $this->flag_filter = 'all';
            }
            $settings = CFG_Click_Fraud_Guard::get_settings();
            $this->repeat_threshold = max(1, (int)$settings['repeat_threshold']);
            $total_items = CFG_Click_Fraud_Guard::get_logs_count($this->excluded_filter, $this->flag_filter, $this->repeat_threshold);

            $this->set_pagination_args(array(
                'total_items' => $total_items,
                'per_page' => $per_page,
            ));

            $this->_column_headers = array($this->get_columns(), array(), array());
            $this->items = CFG_Click_Fraud_Guard::get_logs($per_page, ($current_page - 1) * $per_page, $this->excluded_filter, $this->flag_filter, $this->repeat_threshold);
            $ips = array();
            foreach ($this->items as $item) {
                $ips[] = $item->ip;
            }
            $this->excluded_map = CFG_Click_Fraud_Guard::get_excluded_map($ips);
        }

        protected function get_views() {
            $current_excluded = $this->excluded_filter;
            $current_flag = $this->flag_filter;
            $base_url = admin_url('admin.php?page=click-fraud-guard-logs');
            $views = array();

            $count_all = CFG_Click_Fraud_Guard::get_logs_count('all', 'all', $this->repeat_threshold);
            $count_excluded = CFG_Click_Fraud_Guard::get_logs_count('excluded', $current_flag, $this->repeat_threshold);
            $count_not_excluded = CFG_Click_Fraud_Guard::get_logs_count('not_excluded', $current_flag, $this->repeat_threshold);
            $count_flagged = CFG_Click_Fraud_Guard::get_logs_count($current_excluded, 'flagged', $this->repeat_threshold);
            $count_not_flagged = CFG_Click_Fraud_Guard::get_logs_count($current_excluded, 'not_flagged', $this->repeat_threshold);

            $views['all'] = sprintf(
                '<a href="%s"%s>All <span class="count">(%d)</span></a>',
                esc_url($base_url),
                ($current_excluded === 'all' && $current_flag === 'all') ? ' class="current"' : '',
                $count_all
            );
            $views['flagged'] = sprintf(
                '<a href="%s"%s>Flagged <span class="count">(%d)</span></a>',
                esc_url(add_query_arg(array('flagged' => 'flagged', 'excluded' => $current_excluded), $base_url)),
                $current_flag === 'flagged' ? ' class="current"' : '',
                $count_flagged
            );
            $views['not_flagged'] = sprintf(
                '<a href="%s"%s>Not Flagged <span class="count">(%d)</span></a>',
                esc_url(add_query_arg(array('flagged' => 'not_flagged', 'excluded' => $current_excluded), $base_url)),
                $current_flag === 'not_flagged' ? ' class="current"' : '',
                $count_not_flagged
            );
            $views['excluded'] = sprintf(
                '<a href="%s"%s>Excluded <span class="count">(%d)</span></a>',
                esc_url(add_query_arg(array('excluded' => 'excluded', 'flagged' => $current_flag), $base_url)),
                $current_excluded === 'excluded' ? ' class="current"' : '',
                $count_excluded
            );
            $views['not_excluded'] = sprintf(
                '<a href="%s"%s>Not Excluded <span class="count">(%d)</span></a>',
                esc_url(add_query_arg(array('excluded' => 'not_excluded', 'flagged' => $current_flag), $base_url)),
                $current_excluded === 'not_excluded' ? ' class="current"' : '',
                $count_not_excluded
            );
            return $views;
        }

        public function process_bulk_action() {
            if ($this->current_action() !== 'delete') {
                return;
            }
            check_admin_referer('bulk-logs');
            $ids = isset($_POST['log_id']) ? (array)$_POST['log_id'] : array();
            $this->deleted_count = CFG_Click_Fraud_Guard::delete_logs_by_ids($ids);
        }
    }
}

CFG_Click_Fraud_Guard::init();
