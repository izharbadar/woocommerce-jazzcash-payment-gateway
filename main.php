<?php
/**
 * Plugin Name: WooCommerce JazzCash Gateway (Card + Mobile Wallet v1.1)
 * Description: Accept JazzCash via Card Redirection v1.1 and Mobile Wallet (v1.1 MSISDN-only). Includes IPN + admin Status Inquiry. Uses pgw endpoints for Wallet v1.1 & Inquiry (live).
 * Version:     0.5.0
 * Author:      Izhar Ali
 * License:     GPLv2 or later
 */

if ( ! defined('ABSPATH') ) { exit; }

/** =================== Common helpers (outside classes so IPN route always loads) =================== */

if ( ! function_exists('wc_jazzcash_log') ) {
function wc_jazzcash_log($msg){
    if ( function_exists('wc_get_logger') ) {
        wc_get_logger()->info( $msg, array( 'source' => 'wc-jazzcash' ) );
    }
}}

if ( ! function_exists('wc_jazzcash_now_pk') ) {
function wc_jazzcash_now_pk($format='YmdHis', $offset_days=0){
    $dt = new DateTime( 'now', new DateTimeZone( 'Asia/Karachi' ) );
    if ( $offset_days ) { $dt->modify( sprintf('+%d days', $offset_days) ); }
    return $dt->format($format);
}}

if ( ! function_exists('wc_jazzcash_hmac_values') ) {
function wc_jazzcash_hmac_values($params, $salt, $mode='prepend'){
    // Keep only non-empty pp_* (and ppmpf_*) keys, exclude pp_SecureHash; sort A-Z by key; join VALUES with &
    $salt = trim( (string) $salt );
    $filtered = array();
    foreach( (array) $params as $k=>$v ){
        if ( $k === 'pp_SecureHash' ) continue;
        if ( stripos($k,'pp_') !== 0 && stripos($k,'ppmpf_') !== 0 ) continue;
        if ( $v === null ) continue;
        $sv = trim( (string) $v );
        if ( $sv === '' ) continue;
        $filtered[$k] = $sv;
    }
    ksort($filtered, SORT_STRING);
    $vals = array_values($filtered);
    $base = implode('&', $vals);
    $message = ($mode === 'append') ? ($base . '&' . $salt) : ($salt . '&' . $base);
    return strtoupper( hash_hmac('sha256', $message, $salt) );
}}

if ( ! function_exists('wc_jazzcash_get_gateway_settings') ) {
function wc_jazzcash_get_gateway_settings($wallet=false){
    $opt_key = $wallet ? 'woocommerce_jazzcash_wallet_settings' : 'woocommerce_jazzcash_settings';
    $opts = get_option($opt_key, array());
    return array(
        'merchant_id' => isset($opts['merchant_id']) ? trim($opts['merchant_id']) : '',
        'password'    => isset($opts['password']) ? trim($opts['password']) : '',
        'salt'        => isset($opts['integrity_salt']) ? trim($opts['integrity_salt']) : '',
        'hash_mode'   => isset($opts['hash_mode']) ? $opts['hash_mode'] : 'prepend',
        'sandbox'     => (isset($opts['sandbox']) && $opts['sandbox'] === 'yes'),
        'wallet_api_version' => isset($opts['wallet_api_version']) ? $opts['wallet_api_version'] : '1_1', // not critical now
    );
}}

/** =================== IPN route registered globally (not inside classes) =================== */
add_action('rest_api_init', function(){
    register_rest_route('jazzcash/v1', '/ipn', array(
        'methods'  => 'POST',
        'callback' => 'wc_jazzcash_handle_ipn',
        'permission_callback' => '__return_true',
    ));
});

function wc_jazzcash_handle_ipn( WP_REST_Request $request ){
    // Read JSON
    $raw = $request->get_body();
    $payload = json_decode($raw, true);

    // Prepare default response shape JazzCash expects
    $wallet = wc_jazzcash_get_gateway_settings(true);
    $card   = wc_jazzcash_get_gateway_settings(false);
    $salt   = $wallet['salt'] ? $wallet['salt'] : $card['salt'];
    $mode   = $wallet['hash_mode'] ? $wallet['hash_mode'] : ($card['hash_mode'] ? $card['hash_mode'] : 'prepend');

    $response = array(
        'pp_ResponseCode'    => '000',
        'pp_ResponseMessage' => 'Success',
    );
    $response['pp_SecureHash'] = wc_jazzcash_hmac_values($response, $salt, $mode);

    if ( ! is_array($payload) ){
        wc_jazzcash_log('IPN: Invalid JSON body: ' . $raw);
        return new WP_REST_Response( $response, 200 );
    }

    // Determine salt/mode using TxnType if present
    $is_wallet = isset($payload['pp_TxnType']) && strtoupper($payload['pp_TxnType']) === 'MWALLET';
    $salt_in   = $is_wallet ? $wallet['salt'] : $card['salt'];
    $mode_in   = $is_wallet ? $wallet['hash_mode'] : $card['hash_mode'];
    if ( empty($salt_in) ){ $salt_in = $salt; }
    if ( empty($mode_in) ){ $mode_in = $mode; }

    // Verify incoming hash (non-fatal)
    $received_hash = isset($payload['pp_SecureHash']) ? strtoupper( trim($payload['pp_SecureHash']) ) : '';
    $verify = $payload;
    unset($verify['pp_SecureHash']);
    $calculated = wc_jazzcash_hmac_values($verify, $salt_in, $mode_in);

    wc_jazzcash_log('IPN: payload: ' . print_r($payload, true) . ' Calculated: ' . $calculated);

    $hash_ok = ($received_hash && $received_hash === $calculated);

    // Try mapping to Woo order via TxnRef
    $txn_ref = isset($payload['pp_TxnRefNo']) ? sanitize_text_field($payload['pp_TxnRefNo']) : '';
    if ( $txn_ref ){
        $orders = wc_get_orders( array(
            'limit'        => 1,
            'meta_key'     => '_jazzcash_txn_ref',
            'meta_value'   => $txn_ref,
            'meta_compare' => '=',
        ) );
        if ( ! empty($orders) ){
            $order = $orders[0];

            // 121 = paid
            $resp_code = isset($payload['pp_ResponseCode']) ? (string)$payload['pp_ResponseCode'] : '';
            $pay_code  = isset($payload['pp_PaymentResponseCode']) ? (string)$payload['pp_PaymentResponseCode'] : '';
            $code      = ($pay_code !== '') ? $pay_code : $resp_code;
            $resp_msg  = isset($payload['pp_ResponseMessage']) ? (string)$payload['pp_ResponseMessage'] : '';

            if ( $hash_ok && $code === '121' ){
                $rrn = isset($payload['pp_RetreivalReferenceNo']) ? $payload['pp_RetreivalReferenceNo']
                     : (isset($payload['pp_RetrievalReferenceNo']) ? $payload['pp_RetrievalReferenceNo'] : '');
                if ( $order->has_status( array('pending','on-hold','failed') ) ){
                    $order->payment_complete( $rrn );
                    $order->add_order_note( 'JazzCash IPN success: ' . $resp_msg );
                }
            } elseif ( $hash_ok && $code && $code !== '121' ) {
                $order->update_status('failed', 'JazzCash IPN failed: ' . $resp_msg . ' (code ' . $code . ')' );
            } else {
                $order->add_order_note( 'JazzCash IPN hash mismatch/invalid. Received: ' . $received_hash . ' Calculated: ' . $calculated );
            }
        }
    }

    // Always return success to stop retries
    return new WP_REST_Response( $response, 200 );
}

/** =================== The gateways (card + wallet + admin inquiry) =================== */

add_action( 'plugins_loaded', function() {

    if ( ! class_exists( 'WC_Payment_Gateway' ) ) { return; }

    abstract class WC_Gateway_JazzCash_Base extends WC_Payment_Gateway {

        protected $hash_mode = 'prepend'; // prepend or append

        protected function now_pk_time( $format = 'YmdHis', $offset_days = 0 ) {
            return wc_jazzcash_now_pk($format, $offset_days);
        }

        protected function build_txn_ref( $prefix ) {
            return substr( preg_replace( '/[^A-Za-z]/', '', $prefix ) . $this->now_pk_time(), 0, 3 ) . $this->now_pk_time() . wp_rand(10, 99);
        }

        protected function compute_secure_hash( $params, $integrity_salt, $exclude_keys = array() ) {
            $exclude = array_flip( array_merge( array('pp_SecureHash'), $exclude_keys ) );
            $filtered = array();
            foreach ( $params as $k => $v ) {
                if ( isset( $exclude[$k] ) ) { continue; }
                if ( stripos($k, 'pp_') !== 0 && stripos($k, 'ppmpf_') !== 0 ) { continue; }
                if ( $v === null ) { continue; }
                $sv = trim( (string) $v );
                if ( $sv === '' ) { continue; }
                $filtered[$k] = $sv;
            }
            ksort( $filtered, SORT_STRING );
            $vals = array_values( $filtered );
            $values_concat = implode('&', $vals);
            $message = ($this->hash_mode === 'append') ? ($values_concat . '&' . $integrity_salt) : ($integrity_salt . '&' . $values_concat);
            $hash = strtoupper( hash_hmac( 'sha256', $message, $integrity_salt ) );
            wc_jazzcash_log( 'JazzCash hash keys: ' . implode(',', array_keys($filtered)) );
            wc_jazzcash_log( 'JazzCash hash base (' . $this->hash_mode . '): ' . $values_concat );
            wc_jazzcash_log( 'JazzCash calc hash: ' . $hash );
            return $hash;
        }

        protected function log_debug( $msg ) { wc_jazzcash_log($msg); }
    }

    /* ===================== CARD REDIRECTION (v1.1) ===================== */
    class WC_Gateway_JazzCash extends WC_Gateway_JazzCash_Base {

        public function __construct() {
            $this->id                 = 'jazzcash';
            $this->icon               = '';
            $this->method_title       = __( 'JazzCash (Card Redirection)', 'wc-jazzcash' );
            $this->method_description = __( 'Pay via JazzCash (Card Redirection v1.1). Uses IPN to confirm transactions.', 'wc-jazzcash' );
            $this->has_fields         = false;

            $this->init_form_fields();
            $this->init_settings();

            $this->enabled         = $this->get_option( 'enabled', 'no' );
            $this->title           = $this->get_option( 'title', 'JazzCash (Card)' );
            $this->description     = $this->get_option( 'description', 'Pay securely via JazzCash.' );
            $this->merchant_id     = trim( (string) $this->get_option( 'merchant_id' ) );
            $this->password        = trim( (string) $this->get_option( 'password' ) );
            $this->integrity_salt  = trim( (string) $this->get_option( 'integrity_salt' ) );
            $this->sandbox         = ( 'yes' === $this->get_option( 'sandbox', 'yes' ) );
            $this->order_prefix    = $this->get_option( 'order_prefix', 'Sar' );
            $this->expiry_days     = absint( $this->get_option( 'expiry_days', 3 ) );
            $this->debug           = ( 'yes' === $this->get_option( 'debug', 'no' ) );
            $this->hash_mode       = $this->get_option( 'hash_mode', 'prepend' );

            add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );
            add_action( 'woocommerce_receipt_' . $this->id, array( $this, 'receipt_page' ) );
            add_action( 'woocommerce_api_wc_gateway_jazzcash', array( $this, 'handle_return' ) );
        }

        public function init_form_fields() {
            $this->form_fields = array(
                'enabled' => array(
                    'title'   => __( 'Enable/Disable', 'wc-jazzcash' ),
                    'type'    => 'checkbox',
                    'label'   => __( 'Enable JazzCash (Card Redirection)', 'wc-jazzcash' ),
                    'default' => 'no',
                ),
                'title' => array(
                    'title'   => __( 'Title', 'wc-jazzcash' ),
                    'type'    => 'text',
                    'default' => __( 'JazzCash (Card)', 'wc-jazzcash' ),
                ),
                'description' => array(
                    'title'   => __( 'Description', 'wc-jazzcash' ),
                    'type'    => 'textarea',
                    'default' => __( 'Pay securely via JazzCash.', 'wc-jazzcash' ),
                ),
                'merchant_id' => array(
                    'title'   => __( 'Merchant ID', 'wc-jazzcash' ),
                    'type'    => 'text',
                    'default' => '',
                ),
                'password' => array(
                    'title'   => __( 'Password', 'wc-jazzcash' ),
                    'type'    => 'password',
                    'default' => '',
                ),
                'integrity_salt' => array(
                    'title'   => __( 'Integrity Salt (Hash Key)', 'wc-jazzcash' ),
                    'type'    => 'password',
                    'default' => '',
                ),
                'order_prefix' => array(
                    'title'   => __( 'Order/TXN Prefix', 'wc-jazzcash' ),
                    'type'    => 'text',
                    'default' => 'Sar',
                ),
                'expiry_days' => array(
                    'title'   => __( 'Transaction Expiry (days)', 'wc-jazzcash' ),
                    'type'    => 'number',
                    'default' => 3,
                    'desc_tip'=> true,
                ),
                'sandbox' => array(
                    'title'   => __( 'Sandbox Mode', 'wc-jazzcash' ),
                    'type'    => 'checkbox',
                    'label'   => __( 'Enable sandbox (testing) mode', 'wc-jazzcash' ),
                    'default' => 'yes',
                ),
                'debug' => array(
                    'title'   => __( 'Debug Log', 'wc-jazzcash' ),
                    'type'    => 'checkbox',
                    'label'   => __( 'Enable logging', 'wc-jazzcash' ),
                    'default' => 'no',
                ),
                'hash_mode' => array(
                    'title'   => __( 'Hash Mode (advanced)', 'wc-jazzcash' ),
                    'type'    => 'select',
                    'default' => 'prepend',
                    'options' => array( 'prepend' => 'Prepend salt (recommended)', 'append' => 'Append salt (fallback)' ),
                ),
            );
        }

        protected function get_endpoint_url() {
            return $this->sandbox
                ? 'https://sandbox.jazzcash.com.pk/CustomerPortal/transactionmanagement/merchantform/'
                : 'https://payments.jazzcash.com.pk/CustomerPortal/transactionmanagement/merchantform/';
        }

        public function admin_options() {
            echo '<h3>' . esc_html( $this->get_method_title() ) . '</h3>';
            echo wpautop( esc_html( $this->get_method_description() ) );
            parent::admin_options();
            echo '<p><strong>Return URL:</strong> ' . esc_html( home_url( '/?wc-api=wc_gateway_jazzcash' ) ) . '</p>';
            echo '<p><strong>IPN URL (REST):</strong> ' . esc_html( home_url( '/wp-json/jazzcash/v1/ipn' ) ) . '</p>';
        }

        public function process_payment( $order_id ) {
            $order = wc_get_order( $order_id );
            return array('result'=>'success','redirect'=>$order->get_checkout_payment_url(true));
        }

        public function receipt_page( $order_id ) {
            $order = wc_get_order( $order_id );
            echo '<p>' . esc_html__( 'Redirecting to JazzCash...', 'wc-jazzcash' ) . '</p>';
            echo $this->generate_auto_post_form( $order );
        }

        protected function get_base_params( $order ) {
            $amount = (int) round( $order->get_total() * 100 );
            $params = array(
                'pp_Version'            => '1.1',
                'pp_TxnType'            => 'MPAY',
                'pp_Language'           => 'EN',
                'pp_MerchantID'         => $this->merchant_id,
                'pp_Password'           => $this->password,
                'pp_TxnRefNo'           => $this->build_txn_ref( $this->get_option('order_prefix','Sar') ),
                'pp_Amount'             => (string) $amount,
                'pp_TxnCurrency'        => 'PKR',
                'pp_TxnDateTime'        => wc_jazzcash_now_pk(),
                'pp_BillReference'      => 'ORD' . $order->get_id(),
                'pp_Description'        => 'Order' . $order->get_id(), // safe
                'pp_BankID'             => '',
                'pp_ProductID'          => '',
                'pp_TxnExpiryDateTime'  => wc_jazzcash_now_pk('YmdHis', absint($this->get_option('expiry_days',3)) ),
                'pp_ReturnURL'          => home_url( '/?wc-api=wc_gateway_jazzcash' ),
                'pp_SubMerchantID'      => '',
                'ppmpf_1'               => '',
                'ppmpf_2'               => '',
                'ppmpf_3'               => '',
                'ppmpf_4'               => '',
                'ppmpf_5'               => '',
            );
            $order->update_meta_data( '_jazzcash_txn_ref', $params['pp_TxnRefNo'] );
            $order->save();
            return $params;
        }

        protected function generate_auto_post_form( $order ) {
            $endpoint = esc_url( $this->get_endpoint_url() );
            $params   = $this->get_base_params( $order );
            $params['pp_SecureHash'] = $this->compute_secure_hash( $params, $this->integrity_salt );
            wc_jazzcash_log( 'JazzCash card request: ' . wc_print_r( $params, true ) );

            ob_start(); ?>
            <form id="jazzcash_payment_form" method="post" action="<?php echo $endpoint; ?>">
                <?php foreach ( $params as $k => $v ) : ?>
                    <input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>" />
                <?php endforeach; ?>
                <noscript><button type="submit"><?php esc_html_e( 'Pay via JazzCash', 'wc-jazzcash' ); ?></button></noscript>
            </form>
            <script>document.getElementById('jazzcash_payment_form').submit();</script>
            <?php return ob_get_clean();
        }

        public function handle_return() {
            $data = wp_unslash( $_REQUEST );
            $order_id = isset( $data['pp_BillReference'] ) ? intval( preg_replace( '/\D+/', '', $data['pp_BillReference'] ) ) : 0;
            $order = $order_id ? wc_get_order( $order_id ) : false;

            if ( $order ) {
                $received_hash = isset( $data['pp_SecureHash'] ) ? strtoupper( trim( $data['pp_SecureHash'] ) ) : '';
                $verify_params = $data;
                unset( $verify_params['pp_SecureHash'] );
                $calculated = $this->compute_secure_hash( $verify_params, $this->integrity_salt );
                wc_jazzcash_log( 'JazzCash return: ' . wc_print_r( $data, true ) . ' Calculated: ' . $calculated );

                if ( $received_hash === $calculated ) {
                    $order->add_order_note( 'JazzCash return received. Waiting for IPN confirmation.' );
                    wc_reduce_stock_levels( $order->get_id() );
                    WC()->cart->empty_cart();
                    wp_safe_redirect( $this->get_return_url( $order ) );
                    exit;
                } else {
                    $order->update_status( 'failed', 'JazzCash return hash mismatch.' );
                    wc_add_notice( __( 'Payment verification failed (hash mismatch).', 'wc-jazzcash' ), 'error' );
                    wp_safe_redirect( wc_get_checkout_url() );
                    exit;
                }
            }

            wp_safe_redirect( wc_get_checkout_url() );
            exit;
        }
    }

    /* ===================== MOBILE WALLET: ONLY v1.1 (MSISDN-only) ===================== */
    class WC_Gateway_JazzCash_Wallet extends WC_Gateway_JazzCash_Base {

        public function __construct() {
            $this->id                 = 'jazzcash_wallet';
            $this->icon               = '';
            $this->method_title       = __( 'JazzCash Mobile Wallet', 'wc-jazzcash' );
            $this->method_description = __( 'Pay through JazzCash Mobile Wallet (v1.1 MSISDN-only, pgw API). Final status via IPN/Inquiry.', 'wc-jazzcash' );
            $this->has_fields         = true;

            $this->init_form_fields();
            $this->init_settings();

            $this->enabled               = $this->get_option( 'enabled', 'no' );
            $this->title                 = $this->get_option( 'title', 'JazzCash (Mobile Wallet)' );
            $this->description           = $this->get_option( 'description', 'Pay via JazzCash Mobile Wallet.' );
            $this->merchant_id           = trim( (string) $this->get_option( 'merchant_id' ) );
            $this->password              = trim( (string) $this->get_option( 'password' ) );
            $this->integrity_salt        = trim( (string) $this->get_option( 'integrity_salt' ) );
            $this->sandbox               = ( 'yes' === $this->get_option( 'sandbox', 'no' ) ); // kept but not used by v1.1 pgw
            $this->order_prefix          = $this->get_option( 'order_prefix', 'Sar' );
            $this->expiry_days           = absint( $this->get_option( 'expiry_days', 3 ) );
            $this->debug                 = ( 'yes' === $this->get_option( 'debug', 'no' ) );
            $this->hash_mode             = $this->get_option( 'hash_mode', 'prepend' );

            add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );
        }

        public function init_form_fields() {
            $this->form_fields = array(
                'enabled' => array(
                    'title'   => __( 'Enable/Disable', 'wc-jazzcash' ),
                    'type'    => 'checkbox',
                    'label'   => __( 'Enable JazzCash (Mobile Wallet)', 'wc-jazzcash' ),
                    'default' => 'no',
                ),
                'title' => array(
                    'title'   => __( 'Title', 'wc-jazzcash' ),
                    'type'    => 'text',
                    'default' => __( 'JazzCash (Mobile Wallet)', 'wc-jazzcash' ),
                ),
                'description' => array(
                    'title'   => __( 'Description', 'wc-jazzcash' ),
                    'type'    => 'textarea',
                    'default' => __( 'Pay via JazzCash Mobile Wallet.', 'wc-jazzcash' ),
                ),
                'merchant_id' => array(
                    'title'   => __( 'Merchant ID', 'wc-jazzcash' ),
                    'type'    => 'text',
                    'default' => '',
                ),
                'password' => array(
                    'title'   => __( 'Password', 'wc-jazzcash' ),
                    'type'    => 'password',
                    'default' => '',
                ),
                'integrity_salt' => array(
                    'title'   => __( 'Integrity Salt (Hash Key)', 'wc-jazzcash' ),
                    'type'    => 'password',
                    'default' => '',
                ),
                'order_prefix' => array(
                    'title'   => __( 'Order/TXN Prefix', 'wc-jazzcash' ),
                    'type'    => 'text',
                    'default' => 'Sar',
                ),
                'expiry_days' => array(
                    'title'   => __( 'Transaction Expiry (days)', 'wc-jazzcash' ),
                    'type'    => 'number',
                    'default' => 3,
                    'desc_tip'=> true,
                ),
                'sandbox' => array(
                    'title'   => __( 'Sandbox Mode (not used for v1.1 pgw)', 'wc-jazzcash' ),
                    'type'    => 'checkbox',
                    'label'   => __( 'Has no effect for v1.1 pgw wallet', 'wc-jazzcash' ),
                    'default' => 'no',
                ),
                'debug' => array(
                    'title'   => __( 'Debug Log', 'wc-jazzcash' ),
                    'type'    => 'checkbox',
                    'label'   => __( 'Enable logging', 'wc-jazzcash' ),
                    'default' => 'no',
                ),
                'hash_mode' => array(
                    'title'   => __( 'Hash Mode (advanced)', 'wc-jazzcash' ),
                    'type'    => 'select',
                    'default' => 'prepend',
                    'options' => array( 'prepend' => 'Prepend salt (recommended)', 'append' => 'Append salt (fallback)' ),
                ),
            );
        }

        public function payment_fields() {
            if ( $this->description ) echo wpautop( wp_kses_post( $this->description ) );
            ?>
            <fieldset id="jazzcash-wallet-fields">
                <p class="form-row form-row-first">
                    <label for="jazzcash_wallet_mobile"><?php esc_html_e( 'Mobile Number (03XXXXXXXXX)', 'wc-jazzcash' ); ?> <span class="required">*</span></label>
                    <input id="jazzcash_wallet_mobile" name="jazzcash_wallet_mobile" type="text" autocomplete="tel" placeholder="03XXXXXXXXX" />
                </p>
                <div class="clear"></div>
            </fieldset>
            <?php
        }

        public function validate_fields() {
            $mobile = isset($_POST['jazzcash_wallet_mobile']) ? wc_clean( wp_unslash( $_POST['jazzcash_wallet_mobile'] ) ) : '';
            $mobile = preg_replace('/\D+/', '', $mobile);
            if ( strlen( $mobile ) < 10 ) {
                wc_add_notice( __( 'Please enter a valid mobile number.', 'wc-jazzcash' ), 'error' );
                return false;
            }
            return true;
        }

        protected function wallet_endpoint() {
            // Only v1.1 pgw endpoint is used now (LIVE host as per JazzCash)
            return 'https://pgw.jazzcash.com.pk/api/payment/DoTransaction';
        }

        public function process_payment( $order_id ) {
            $order  = wc_get_order( $order_id );
            $mobile = isset($_POST['jazzcash_wallet_mobile']) ? wc_clean( wp_unslash( $_POST['jazzcash_wallet_mobile'] ) ) : '';
            $mobile = preg_replace('/\D+/', '', $mobile);

            $amount = (int) round( $order->get_total() * 100 );
            $txnRef = $this->build_txn_ref( $this->get_option('order_prefix','Sar') );

            // v1.1 (MSISDN-only @ pgw)
            $params = array(
                'pp_Version'           => '1.1',
                'pp_TxnType'           => 'MWALLET',
                'pp_Amount'            => (string) $amount,
                'pp_BillReference'     => 'ORD' . $order->get_id(),
                'pp_Description'       => 'Order' . $order->get_id(),
                'pp_Language'          => 'EN',
                'pp_MerchantID'        => $this->merchant_id,
                'pp_MobileNumber'      => $mobile,
                'pp_Password'          => $this->password,
                'pp_TxnCurrency'       => 'PKR',
                'pp_TxnDateTime'       => wc_jazzcash_now_pk(),
                'pp_TxnExpiryDateTime' => wc_jazzcash_now_pk('YmdHis', absint($this->get_option('expiry_days',3)) ),
                'pp_TxnRefNo'          => $txnRef,
                // Optional meta (avoid empty → some gateways reject empties)
                'ppmpf_1' => 'WALLET_V1.1',
                'ppmpf_2' => (string) $order->get_billing_first_name(),
                'ppmpf_3' => (string) $order->get_billing_email(),
                'ppmpf_4' => (string) $order->get_billing_phone(),
                'ppmpf_5' => '',
            );
            // v1.1: include TxnType/Version in hash (no exclusions)
            $params['pp_SecureHash'] = $this->compute_secure_hash( $params, $this->integrity_salt );

            // store meta
            $order->update_meta_data( '_jazzcash_txn_ref', $txnRef );
            $order->update_meta_data( '_jazzcash_wallet_mobile', $mobile );
            $order->save();

            // POST (JSON) to wallet endpoint
            $resp = wp_remote_post( $this->wallet_endpoint(), array(
                'headers' => array( 'Content-Type' => 'application/json' ),
                'body'    => wp_json_encode( $params ),
                'timeout' => 30,
            ) );

            if ( is_wp_error( $resp ) ) {
                wc_add_notice( __( 'Could not reach JazzCash. Please try again.', 'wc-jazzcash' ), 'error' );
                $this->log_debug( 'MWallet HTTP error: ' . $resp->get_error_message() );
                return;
            }

            $body = wp_remote_retrieve_body( $resp );
            $json = json_decode( $body, true );
            $this->log_debug( 'MWallet response: ' . $body );

            $response_code = isset( $json['pp_ResponseCode'] ) ? (string) $json['pp_ResponseCode'] : '';
            $response_msg  = isset( $json['pp_ResponseMessage'] ) ? (string) $json['pp_ResponseMessage'] : '';

            // For v1.1, treat '000' as "accepted/initiated" and rely on IPN/Inquiry to mark paid (121)
            if ( $response_code === '000' ) {
                $order->add_order_note( 'JazzCash Mobile Wallet initiated (v1.1): ' . $response_msg );
                WC()->cart->empty_cart();
                return array( 'result'=>'success','redirect'=>$this->get_return_url($order) );
            } else {
                $order->update_status( 'failed', 'JazzCash Mobile Wallet failed to initiate: ' . $response_msg . ' (code ' . $response_code . ')' );
                wc_add_notice( __( 'Wallet payment failed to initiate: ', 'wc-jazzcash' ) . $response_msg, 'error' );
                return;
            }
        }
    }

    // ===================== ADMIN: STATUS INQUIRY (admin-only) =====================

    if ( ! function_exists('wc_jazzcash_compute_hash_simple') ) {
    function wc_jazzcash_compute_hash_simple( $params, $salt, $mode = 'prepend' ) {
        return wc_jazzcash_hmac_values($params, $salt, $mode);
    }}

    if ( ! function_exists('wc_jazzcash_get_settings_for') ) {
    function wc_jazzcash_get_settings_for( $method = 'wallet' ) {
        $opt_key = ($method === 'card') ? 'woocommerce_jazzcash_settings' : 'woocommerce_jazzcash_wallet_settings';
        $opts = get_option( $opt_key, array() );
        return array(
            'merchant_id' => isset($opts['merchant_id']) ? trim($opts['merchant_id']) : '',
            'password'    => isset($opts['password']) ? trim($opts['password']) : '',
            'salt'        => isset($opts['integrity_salt']) ? trim($opts['integrity_salt']) : '',
            'sandbox'     => (isset($opts['sandbox']) && $opts['sandbox'] === 'yes'),
            'hash_mode'   => isset($opts['hash_mode']) ? $opts['hash_mode'] : 'prepend',
            'wallet_api_version' => isset($opts['wallet_api_version']) ? $opts['wallet_api_version'] : '1_1',
        );
    }}

    if ( ! function_exists('wc_jazzcash_inquiry_endpoint') ) {
    function wc_jazzcash_inquiry_endpoint( $sandbox = true ) {
        // v1.1 live → pgw host as per JazzCash instruction; sandbox uses standard host
        return $sandbox
            ? 'https://sandbox.jazzcash.com.pk/ApplicationAPI/API/PaymentInquiry/Inquire'
            : 'https://pgw.jazzcash.com.pk/ApplicationAPI/API/PaymentInquiry/Inquire';
    }}

    if ( ! function_exists('wc_jazzcash_do_inquiry') ) {
    function wc_jazzcash_do_inquiry( $txn_ref, $method = 'wallet' ) {
        $s = wc_jazzcash_get_settings_for( $method );
        $params = array(
            'pp_MerchantID' => $s['merchant_id'],
            'pp_Password'   => $s['password'],
            'pp_TxnRefNo'   => $txn_ref,
        );
        $params['pp_SecureHash'] = wc_jazzcash_compute_hash_simple( $params, $s['salt'], $s['hash_mode'] );
        $resp = wp_remote_post( wc_jazzcash_inquiry_endpoint( $s['sandbox'] ), array(
            'headers' => array( 'Content-Type' => 'application/json' ),
            'body'    => wp_json_encode( $params ),
            'timeout' => 30,
        ) );
        if ( is_wp_error( $resp ) ) {
            return array( 'error' => $resp->get_error_message() );
        }
        $body = wp_remote_retrieve_body( $resp );
        $json = json_decode( $body, true );
        if ( ! is_array( $json ) ) {
            return array( 'error' => 'Invalid JSON from gateway', 'raw' => $body );
        }
        return $json;
    }}

    add_action( 'admin_menu', function() {
        add_submenu_page(
            'woocommerce',
            'JazzCash Status Inquiry',
            'JazzCash Status Inquiry',
            'manage_woocommerce',
            'wc-jazzcash-inquiry',
            'wc_jazzcash_render_inquiry_page'
        );
    } );

    if ( ! function_exists('wc_jazzcash_render_inquiry_page') ) {
    function wc_jazzcash_render_inquiry_page() {
        if ( ! current_user_can( 'manage_woocommerce' ) ) { wp_die('Unauthorized'); }
        $result = null; $note = '';
        if ( isset($_POST['wc_jazzcash_do_inquiry']) && check_admin_referer('wc_jazzcash_inquiry') ) {
            $order_id = isset($_POST['order_id']) ? intval($_POST['order_id']) : 0;
            $txn_ref  = isset($_POST['txn_ref']) ? sanitize_text_field($_POST['txn_ref']) : '';
            $method   = isset($_POST['method']) ? sanitize_text_field($_POST['method']) : 'auto';
            $update_order = ! empty($_POST['update_order']);

            if ( $order_id && empty($txn_ref) ) {
                $order = wc_get_order( $order_id );
                if ( $order ) {
                    $txn_ref = $order->get_meta('_jazzcash_txn_ref');
                    if ( $method === 'auto' ) {
                        $pm = $order->get_payment_method();
                        if ( $pm === 'jazzcash_wallet' ) { $method = 'wallet'; }
                        elseif ( $pm === 'jazzcash' ) { $method = 'card'; }
                        else { $method = 'wallet'; }
                    }
                }
            }
            if ( $method === 'auto' ) { $method = 'wallet'; }
            if ( $txn_ref ) {
                $result = wc_jazzcash_do_inquiry( $txn_ref, $method );
                if ( $update_order && $order_id && is_array($result) && ( isset($result['pp_PaymentResponseCode']) || isset($result['pp_ResponseCode']) ) ) {
                    $order = wc_get_order( $order_id );
                    if ( $order ) {
                        $code = isset($result['pp_PaymentResponseCode']) ? (string)$result['pp_PaymentResponseCode']
                              : ( isset($result['pp_ResponseCode']) ? (string)$result['pp_ResponseCode'] : '' );
                        $msg  = isset($result['pp_PaymentResponseMessage']) ? $result['pp_PaymentResponseMessage']
                              : ( isset($result['pp_ResponseMessage']) ? $result['pp_ResponseMessage'] : '' );
                        if ( $code === '121' ) {
                            $rrn = isset($result['pp_RetreivalReferenceNo']) ? $result['pp_RetreivalReferenceNo']
                                 : (isset($result['pp_RetrievalReferenceNo']) ? $result['pp_RetrievalReferenceNo'] : '');
                            $order->payment_complete( $rrn );
                            $order->add_order_note( 'JazzCash Inquiry success: ' . $msg );
                            $note = 'Order marked paid (code 121).';
                        } else {
                            $order->update_status( 'failed', 'JazzCash Inquiry result: ' . $msg . ' (code ' . $code . ')' );
                            $note = 'Order set to Failed (code ' . esc_html($code) . ').';
                        }
                    }
                }
            } else {
                $result = array( 'error' => 'Provide Order ID or TxnRefNo' );
            }
        }
        ?>
        <div class="wrap">
            <h1>JazzCash Status Inquiry (Admin only)</h1>
            <form method="post">
                <?php wp_nonce_field('wc_jazzcash_inquiry'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">Order ID</th>
                        <td><input type="number" name="order_id" placeholder="e.g. 23159" /></td>
                    </tr>
                    <tr>
                        <th scope="row">TxnRefNo</th>
                        <td><input type="text" name="txn_ref" placeholder="SarYYYYMMDDhhmmssNN" /></td>
                    </tr>
                    <tr>
                        <th scope="row">Payment Method</th>
                        <td>
                            <select name="method">
                                <option value="auto">Auto (use order’s method)</option>
                                <option value="wallet">Wallet</option>
                                <option value="card">Card</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Update Woo order status</th>
                        <td><label><input type="checkbox" name="update_order" value="1" /> If response is 121 (success), mark order paid; otherwise mark failed.</label></td>
                    </tr>
                </table>
                <p><button class="button button-primary" name="wc_jazzcash_do_inquiry" value="1">Run Inquiry</button></p>
            </form>

            <?php if ( $result !== null ) : ?>
                <h2>Gateway Reply</h2>
                <pre style="background:#fff;border:1px solid #ccd0d4;padding:12px;max-width:900px;overflow:auto;"><?php echo esc_html( print_r( $result, true ) ); ?></pre>
                <?php if ( ! empty($note) ) : ?>
                    <p><strong><?php echo esc_html($note); ?></strong></p>
                <?php endif; ?>
            <?php endif; ?>
            <hr/>
            <p><em>Note: This tool is available only to users with <code>manage_woocommerce</code> capability. Do not expose it on the frontend.</em></p>
        </div>
        <?php
    }}

    // Register both gateways
    add_filter( 'woocommerce_payment_gateways', function( $methods ) {
        $methods[] = 'WC_Gateway_JazzCash';
        $methods[] = 'WC_Gateway_JazzCash_Wallet';
        return $methods;
    } );
} );
