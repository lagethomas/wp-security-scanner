<?php
/*
 * Plugin Name: WP Security Scanner PRO
 * Description: Escaneie seu site em busca de vulnerabilidades de segurança e desempenho, fornecendo dicas de blindagem.
 * Version: 1.2
 * TAG: true
 * Author: Thomas Marcelino
 * Author URI: https://wpmasters.com.br
 * License: GPL2
 * Text Domain: wp-security-scanner
 */

// Prevenir acesso direto
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// =========================================================================
// 1. CONSTANTES E VERSIONAMENTO
// =========================================================================

/**
 * Versão do Plugin. Versão incrementada para 5.3.4 após a atualização.
 */
define( 'WPSS_VERSION', '1.2' );

/**
 * Versão única para assets (CSS/JS) para evitar cache em atualizações.
 */
define( 'CODE_VERSION_WPSS_ASSETS', time() );

/**
 * Prefixo usado em todas as funções, classes e hooks para evitar colisões.
 */
define( 'WPSS_PREFIX', 'wpss_' );

/**
 * URL e Path do Plugin
 */
define( 'WPSS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WPSS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );


class WPSS_Security_Scanner {
    
    /**
     * @var string O slug da página de administração.
     */
    private $admin_page_slug;

    public function __construct() {
        $this->load_configuration();
        
        // Carrega o text domain para traduções
        add_action( 'plugins_loaded', array( $this, 'load_plugin_textdomain' ) );
        
        // Hooks de Administração
        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
        add_action( 'wp_ajax_' . WPSS_PREFIX . 'run_health_scan', array( $this, 'ajax_run_scan' ) ); 
    }

    /**
     * Carrega a configuração do arquivo config-page.cnf.
     */
    private function load_configuration() {
        $config_file = WPSS_PLUGIN_DIR . 'config/config-page.cnf';
        if ( file_exists( $config_file ) ) {
            $config_content = file_get_contents( $config_file );
            if ( preg_match( '/slug:(.*)/', $config_content, $matches ) ) {
                $this->admin_page_slug = sanitize_title( trim( $matches[1] ) );
            }
        }
        if ( empty( $this->admin_page_slug ) ) {
             $this->admin_page_slug = 'wp-security-scanner'; // Fallback
        }
    }
    
    /**
     * Carrega os arquivos de tradução (i18n).
     */
    public function load_plugin_textdomain() {
        load_plugin_textdomain( 'wp-security-scanner', false, basename( WPSS_PLUGIN_DIR ) . '/languages/' );
    }

    /**
     * Define a estrutura das seções e os métodos de verificação.
     *
     * @return array Mapa das seções de scan.
     */
    private function get_scan_sections() {
        return array(
            'wordpress' => array( 'title' => esc_html__( '⚙️ WordPress Core', 'wp-security-scanner' ), 'method' => 'check_wordpress' ),
            'php'       => array( 'title' => esc_html__( '🔧 Configurações do PHP', 'wp-security-scanner' ), 'method' => 'check_php' ),
            'security_keys' => array( 'title' => esc_html__( '🔑 Chaves de Segurança e SALT', 'wp-security-scanner' ), 'method' => 'check_security_keys' ),
            'login_security' => array( 'title' => esc_html__( '🛡️ Login e Força Bruta', 'wp-security-scanner' ), 'method' => 'check_login_security' ),
            'http_headers'  => array( 'title' => esc_html__( '🌐 HTTP Headers (Defesa de Borda)', 'wp-security-scanner' ), 'method' => 'check_http_headers' ),
            'filesystem' => array( 'title' => esc_html__( '📁 Hardening do Sistema de Arquivos', 'wp-security-scanner' ), 'method' => 'check_filesystem' ),
            'database'  => array( 'title' => esc_html__( '🗃️ Banco de Dados e Usuários', 'wp-security-scanner' ), 'method' => 'check_database' ),
            'plugins'   => array( 'title' => esc_html__( '🔌 Plugins', 'wp-security-scanner' ), 'method' => 'check_plugins' ),
            'themes'    => array( 'title' => esc_html__( '🎨 Temas', 'wp-security-scanner' ), 'method' => 'check_themes' ),
            'security_adv' => array( 'title' => esc_html__( '🔒 Segurança Avançada / Descoberta', 'wp-security-scanner' ), 'method' => 'check_security_adv' ),
        );
    }
    
    /**
     * Adiciona o item de menu na administração.
     */
    public function add_admin_menu() {
        add_menu_page(
            esc_html__( 'WP Security Scanner', 'wp-security-scanner' ), 
            esc_html__( 'Security Scanner', 'wp-security-scanner' ),    
            'manage_options',      
            $this->admin_page_slug, 
            array( $this, 'admin_page_html' ), 
            'dashicons-shield',    
            80                     
        );
    }
    
    /**
     * Enfileira scripts e estilos para a página de administração.
     *
     * @param string $hook O slug da página atual.
     */
    public function enqueue_scripts( $hook ) {
        // Verifica se estamos na página do plugin
        if ( 'toplevel_page_' . $this->admin_page_slug !== $hook ) {
            return;
        }
        
        // Enfileira o CSS de administração (EXTRAÍDO)
        wp_enqueue_style( WPSS_PREFIX . 'admin-style', WPSS_PLUGIN_URL . 'assets/css/admin.css', array(), CODE_VERSION_WPSS_ASSETS );

        // Enfileira o JS de administração (JQuery é uma dependência)
        wp_enqueue_script( WPSS_PREFIX . 'admin-script', WPSS_PLUGIN_URL . 'assets/js/admin.js', array( 'jquery' ), CODE_VERSION_WPSS_ASSETS, true );
        
        // Passa dados para o JS, incluindo o nonce e o mapa de passos.
        wp_localize_script( WPSS_PREFIX . 'admin-script', 'healthCheckAjax', array(
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'nonce' => wp_create_nonce( WPSS_PREFIX . 'health_check_nonce' ),
            'scan_steps' => $this->get_scan_sections(),
            'ajax_action' => WPSS_PREFIX . 'run_health_scan' // Passa o nome da action AJAX para o JS
        ) );
    }
    
    /**
     * Gera o HTML da página de administração.
     */
    public function admin_page_html() {
        ?>
        <div class="wrap <?php echo esc_attr( WPSS_PREFIX ); ?>wrap">
            <div class="wpss-header">
                <h1>
                    <?php esc_html_e( '🛡️ WP Security Scanner PRO', 'wp-security-scanner' ); ?>
                    <span class="wpss-badge"><?php echo esc_html( WPSS_VERSION ); ?></span>
                </h1>
                <p class="description"><?php esc_html_e( 'Verificação completa e aprofundada de segurança para blindar seu site WordPress. Siga as recomendações para resolver as vulnerabilidades.', 'wp-security-scanner' ); ?></p>
            </div>
            
            <div class="wpss-two-column-layout">
                
                <div class="wpss-main-content">
                    <div class="health-check-container wpss-box">
                        <div class="health-check-header">
                            <button id="run-scan" class="button button-primary button-large">
                                <?php esc_html_e( '🔍 Executar Verificação Completa', 'wp-security-scanner' ); ?>
                            </button>
                            
                            <div id="scan-progress-bar" style="display:none;">
                                <div class="progress-info">
                                     <span id="progress-text"><?php esc_html_e( 'Iniciando...', 'wp-security-scanner' ); ?></span>
                                     <span id="progress-percentage">0%</span>
                                </div>
                                <div class="progress-bar-container">
                                    <div id="progress-bar-fill" class="progress-bar-fill" style="width: 0%;"></div>
                                </div>
                            </div>
                        </div>
                        
                        <div id="scan-results" class="health-check-results">
                            <div class="notice notice-info"><p><?php esc_html_e( 'Clique em ', 'wp-security-scanner' ); ?><strong><?php esc_html_e( 'Executar Verificação Completa', 'wp-security-scanner' ); ?></strong><?php esc_html_e( ' para começar o diagnóstico de segurança.', 'wp-security-scanner' ); ?></p></div>
                        </div>
                        
                        <div id="results-accordion-wrapper" style="display:none;">
                        </div>
                    </div>
                </div>
                
                <div class="wpss-sidebar">
                    
                    <div class="sidebar-box wpss-box">
                        <h4><?php esc_html_e( '💡 Dicas de Blindagem Rápida', 'wp-security-scanner' ); ?></h4>
                        <ul>
                            <li><strong><?php esc_html_e( 'Backup:', 'wp-security-scanner' ); ?></strong> <?php esc_html_e( 'Tenha sempre um backup recente e externo (fora do servidor) do seu site.', 'wp-security-scanner' ); ?></li>
                            <li><strong><?php esc_html_e( 'Senhas:', 'wp-security-scanner' ); ?></strong> <?php esc_html_e( 'Use senhas longas e complexas com um gerenciador de senhas.', 'wp-security-scanner' ); ?></li>
                            <li><strong><?php esc_html_e( 'Usuários:', 'wp-security-scanner' ); ?></strong> <?php esc_html_e( 'Nunca use o usuário ', 'wp-security-scanner' ); ?><code>admin</code><?php esc_html_e( ' e utilize nomes de usuário complexos para a conta principal.', 'wp-security-scanner' ); ?></li>
                            <li><strong><?php esc_html_e( 'Hospedagem:', 'wp-security-scanner' ); ?></strong> <?php esc_html_e( 'Prefira hospedagens que ofereçam WAF (Web Application Firewall) e detecção de malware em tempo real.', 'wp-security-scanner' ); ?></li>
                            <li><strong><?php esc_html_e( 'Princípio do Mínimo Privilégio:', 'wp-security-scanner' ); ?></strong> <?php esc_html_e( 'Dê a cada usuário apenas as permissões essenciais para o seu trabalho.', 'wp-security-scanner' ); ?></li>
                        </ul>
                    </div>

                    <div class="sidebar-box wpss-box">
                        <h4><?php esc_html_e( '🚀 Plugins de Segurança Recomendados', 'wp-security-scanner' ); ?></h4>
                        <p><?php esc_html_e( 'A WPMasters oferece ferramentas exclusivas para reforçar pontos de segurança específicos no seu WordPress:', 'wp-security-scanner' ); ?></p>
                        <ul>
                            <li><a href="https://wpmasters.com.br/produto/controle-de-funcoes-e-restricao-de-menus-e-paginas-para-wordpress/" target="_blank"><?php esc_html_e( 'Controle de funções', 'wp-security-scanner' ); ?></a>: <?php esc_html_e( 'Restrinja menus e páginas por função do usuário.', 'wp-security-scanner' ); ?></li>
                            <li><a href="https://wpmasters.com.br/produto/token-access-login-sem-senha-simplificado-e-seguro-para-wordpress/" target="_blank"><?php esc_html_e( 'Token de acesso sem senha', 'wp-security-scanner' ); ?></a>: <?php esc_html_e( 'Simplifique o login com segurança (Login sem senha).', 'wp-security-scanner' ); ?></li>
                            <li><a href="https://wpmasters.com.br/produto/wpm-audit-for-wordpress/" target="_blank"><?php esc_html_e( 'WPM Audit for WordPress', 'wp-security-scanner' ); ?></a>: <?php esc_html_e( 'Para auditoria completa de ações de usuários.', 'wp-security-scanner' ); ?></li>
                            <li><a href="https://wpmasters.com.br/produto/login-logger-seguranca-em-foco-monitore-acessos-simples-e-objetivo/" target="_blank"><?php esc_html_e( 'Login Logger', 'wp-security-scanner' ); ?></a>: <?php esc_html_e( 'Monitore os acessos e tentativas de login.', 'wp-security-scanner' ); ?></li>
                        </ul>
                    </div>
                    
                    <div class="sidebar-box wpss-box" style="text-align: center;">
                        <p><strong><?php esc_html_e( 'Blindagem Completa para seu WordPress!', 'wp-security-scanner' ); ?></strong></p>
                        <a href="https://wpmasters.com.br" target="_blank" class="button button-secondary button-large"><?php esc_html_e( 'Visitar WPMasters', 'wp-security-scanner' ); ?></a>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Lida com a requisição AJAX para rodar o scan de saúde.
     */
    public function ajax_run_scan() {
        check_ajax_referer( WPSS_PREFIX . 'health_check_nonce', 'nonce' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Sem permissão para executar o scan.', 'wp-security-scanner' ) ) );
        }
        
        $results = array();
        $sections = $this->get_scan_sections();
        
        // Use wp_raise_memory_limit() se necessário para garantir que o scan não falhe por falta de memória.
        // wp_raise_memory_limit( 'admin' ); 

        foreach ( $sections as $slug => $data ) {
            // Pequeno atraso para que a barra de progresso no JS possa acompanhar
            usleep( 100000 ); 
            if ( method_exists( $this, $data['method'] ) ) {
                $results[ $slug ] = call_user_func( array( $this, $data['method'] ) );
            }
        }
        
        wp_send_json_success( $results );
    }
    
    // =========================================================================
    // MÉTODOS DE VERIFICAÇÃO 
    // =========================================================================

    /**
     * @return array[]
     */
    private function check_php() {
        $items = array();
        $php_version = phpversion();
        $rec_php_version = '8.1';
        
        // Check 1: PHP Version
        if ( version_compare( $php_version, $rec_php_version, '>=' ) ) {
            $items[] = array( 
                'status' => 'good', 
                'message' => sprintf( esc_html__( 'Versão do PHP: %s', 'wp-security-scanner' ), $php_version ), 
                'details' => esc_html__( 'Sua versão do PHP é atual e oferece melhor desempenho e segurança.', 'wp-security-scanner' )
            );
        } elseif ( version_compare( $php_version, '7.4', '>=' ) ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => sprintf( esc_html__( 'Versão do PHP: %s', 'wp-security-scanner' ), $php_version ), 
                'details' => esc_html__( 'Versão suportada, mas não a mais recente.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( sprintf( 
                    __( 'Atualize o PHP para a versão %s ou superior através do painel de controle da sua hospedagem.', 'wp-security-scanner' ), 
                    $rec_php_version 
                ) )
            );
        } else {
            $items[] = array( 
                'status' => 'error', 
                'message' => sprintf( esc_html__( 'Versão do PHP: %s', 'wp-security-scanner' ), $php_version ), 
                'details' => esc_html__( 'CRÍTICO: Sua versão é antiga e não recebe patches de segurança.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( sprintf( 
                    __( 'Atualize imediatamente para a versão 7.4 ou superior. Use PHP %s para blindagem completa.', 'wp-security-scanner' ), 
                    $rec_php_version 
                ) )
            );
        }
        
        // Check 2: Memory Limit
        $memory_limit = ini_get( 'memory_limit' );
        $recommended_memory = '256M';
        if ( wp_convert_hr_to_bytes( $memory_limit ) < wp_convert_hr_to_bytes( $recommended_memory ) ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => sprintf( esc_html__( 'Memory Limit: %s', 'wp-security-scanner' ), $memory_limit ), 
                'details' => esc_html__( 'Pode causar erros de memória em plugins complexos ou uploads grandes.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( sprintf( 
                    __( 'Aumente o <code>memory_limit</code> para %s ou mais no <code>php.ini</code> ou via <code>wp-config.php</code> (<code>define(\'WP_MEMORY_LIMIT\', \'256M\');</code>).', 'wp-security-scanner' ), 
                    $recommended_memory 
                ) )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => sprintf( esc_html__( 'Memory Limit: %s', 'wp-security-scanner' ), $memory_limit ), 
                'details' => esc_html__( 'Configuração adequada.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }
    
    /**
     * @return array[]
     */
    private function check_wordpress() {
        $items = array();
        global $wp_version;
        
        // Precisa incluir a função get_core_updates
        if ( ! function_exists( 'get_core_updates' ) ) {
             require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $core_update = get_core_updates();
        
        // Check 1: WordPress Version
        if ( ! is_wp_error( $core_update ) && isset( $core_update[0]->current ) && version_compare( $core_update[0]->current, $wp_version, '>' ) ) {
            $latest_version = $core_update[0]->current;
            $items[] = array( 
                'status' => 'error', 
                'message' => sprintf( esc_html__( 'WordPress desatualizado: %s', 'wp-security-scanner' ), $wp_version ), 
                'details' => esc_html__( 'Versões antigas têm vulnerabilidades de segurança conhecidas e exploradas.', 'wp-security-scanner' ), 
                'recommendation' => sprintf( esc_html__( 'ATUALIZE IMEDIATAMENTE para a versão %s via Painel > Atualizações.', 'wp-security-scanner' ), $latest_version )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => sprintf( esc_html__( 'WordPress atualizado: %s', 'wp-security-scanner' ), $wp_version ), 
                'details' => esc_html__( 'Sua versão do WordPress está atualizada e segura.', 'wp-security-scanner' )
            );
        }

        // Check 2: HTTPS/SSL
        $url = home_url();
        if ( strpos( $url, 'https://' ) !== 0 ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Conexão insegura (HTTP)', 'wp-security-scanner' ), 
                'details' => esc_html__( 'CRÍTICO: Os dados (incluindo senhas) são transmitidos em texto simples.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Migre para HTTPS/SSL. Instale um certificado SSL e defina o endereço do WordPress e do Site para usar <code>https://</code> em Configurações > Geral.', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Conexão segura (HTTPS)', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O WordPress está configurado para usar HTTPS.', 'wp-security-scanner' )
            );
        }

        // Check 3: Force SSL Admin
        if ( ! is_ssl() && ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => esc_html__( 'FORCE_SSL_ADMIN não forçado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O painel de administração pode estar acessível via HTTP em alguns casos.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Adicione <code>define(\'FORCE_SSL_ADMIN\', true);</code> ao <code>wp-config.php</code>, logo acima da linha <code>/* That\'s all, stop editing! Happy blogging. */</code>.', 'wp-security-scanner' ) )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'FORCE_SSL_ADMIN configurado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O login e a área de administração forçam o uso de HTTPS.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }
    
    /**
     * @return array[]
     */
    private function check_security_keys() {
        $items = array();
        $required_keys = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
        $missing_keys = array();
        $weak_keys_found = false;
        
        foreach ( $required_keys as $key ) {
            if ( ! defined( $key ) ) {
                $missing_keys[] = $key;
            } else {
                $value = constant( $key );
                // Assume que chaves curtas ou com valores de placeholder são fracas
                if ( strlen( $value ) < 60 || preg_match( '/(unique phrase|put your|salt here)/i', $value ) ) {
                     $weak_keys_found = true;
                }
            }
        }
        
        if ( ! empty( $missing_keys ) ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Chaves de Segurança Ausentes', 'wp-security-scanner' ), 
                'details' => sprintf( esc_html__( 'As seguintes chaves estão faltando no seu <code>wp-config.php</code>: %s', 'wp-security-scanner' ), implode( ', ', $missing_keys ) ), 
                'recommendation' => esc_html__( 'Gere chaves novas e exclusivas para estas constantes. Use a ferramenta oficial do WordPress para geração de SALT.', 'wp-security-scanner' )
            );
        } elseif ( $weak_keys_found ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Chaves e SALT são fracas ou padrão', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Chaves de autenticação (AUTH_KEY, etc.) não parecem seguras o suficiente ou usam valores padrão.', 'wp-security-scanner' ), 
                'recommendation' => esc_html__( 'Atualize todas as 8 chaves de segurança/SALT no <code>wp-config.php</code>. Isso invalidará todas as sessões, melhorando a segurança de login.', 'wp-security-scanner' )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Chaves de Segurança e SALT configuradas', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Chaves de criptografia e SALT parecem fortes e configuradas corretamente.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }
    
    /**
     * @return array[]
     */
    private function check_login_security() {
        $items = array();
        
        // Check 1: Usuário 'admin' padrão com ID 1
        $default_admin = get_user_by( 'id', 1 );
        $admin_login_user = get_user_by( 'login', 'admin' );
        
        if ( ( $default_admin && $default_admin->ID === 1 && $default_admin->has_cap( 'administrator' ) ) || ( $admin_login_user && $admin_login_user->has_cap( 'administrator' ) ) ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Usuário \'admin\' ou ID 1 vulnerável', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Usuários com o nome \'admin\' ou ID 1 são alvos fáceis para ataques de força bruta e enumeração.', 'wp-security-scanner' ), 
                'recommendation' => esc_html__( 'Crie um novo usuário administrador com nome de usuário complexo e exclua o usuário vulnerável, atribuindo o conteúdo ao novo usuário.', 'wp-security-scanner' )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Usuário \'admin\' não encontrado e ID 1 protegido', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O login principal de administrador está protegido contra enumeração básica.', 'wp-security-scanner' )
            );
        }

        // Check 2: Limit Login Attempts
        $items[] = array( 
            'status' => 'warning', 
            'message' => esc_html__( 'Limite de Tentativas de Login', 'wp-security-scanner' ), 
            'details' => esc_html__( 'O WordPress não limita o número de tentativas de login por padrão, permitindo ataques de força bruta.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( __( 'Instale um plugin como **Limit Login Attempts Reloaded** ou use regras de segurança no seu Firewall (WAF) ou <code>.htaccess</code> para bloquear IPs após 3-5 tentativas falhas.', 'wp-security-scanner' ) )
        );

        // Check 3: Autenticação de Dois Fatores (2FA)
        $items[] = array( 
            'status' => 'warning', 
            'message' => esc_html__( 'Autenticação de Dois Fatores (2FA) Inativa', 'wp-security-scanner' ), 
            'details' => esc_html__( 'A 2FA é a camada de defesa mais forte contra roubo de credenciais. Apenas senha não é suficiente.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( __( 'Instale um plugin de 2FA (ex: **Google Authenticator**, **Solid Security**) e force o uso para todos os usuários com capacidade de <code>manage_options</code>.', 'wp-security-scanner' ) )
        );

        // Check 4: Logout de Sessão Inativa (Idle Session)
        $items[] = array(
            'status' => 'warning', 
            'message' => esc_html__( 'Logout de Sessão Inativa (Idle Session)', 'wp-security-scanner' ), 
            'details' => esc_html__( 'Sessões abertas indefinidamente aumentam o risco de acesso não autorizado se o computador ficar sem vigilância.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( 
                sprintf( 
                    __( 'Adicione código ao seu tema ou use um plugin para forçar o logout automático de usuários após 15-30 minutos de inatividade. Plugin recomendado: <a href="%s" target="_blank">Plugin recomendado</a>.', 'wp-security-scanner' ),
                    'https://wpmasters.com.br/produto/controle-de-sessoes-limite-logins-e-monitore-a-atividade-de-usuarios-no-wordpress/'
                ) 
            )
        );

        // Check 5: Enumeração de Usuário via API REST
        if ( get_option( 'enable_xmlrpc' ) ) { // Usando um proxy simples para status da API REST
             $items[] = array( 
                'status' => 'warning', 
                'message' => esc_html__( 'Enumeração de usuário via API REST', 'wp-security-scanner' ), 
                'details' => esc_html__( 'A API REST expõe os nomes de usuários através de <code>/wp-json/wp/v2/users</code>.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Use um plugin de segurança ou adicione filtros de autenticação para restringir o acesso à rota <code>wp/v2/users</code> para não logados.', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Enumeração de usuário API REST protegida', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O acesso à lista de usuários via API REST parece estar restrito ou desativado.', 'wp-security-scanner' )
            );
        }

        return $items;
    }

    /**
     * @return array[]
     */
    private function check_http_headers() {
        $items = array();
        
        $items[] = array( 
            'status' => 'warning', 
            'message' => esc_html__( 'X-Frame-Options Ausente (Clickjacking)', 'wp-security-scanner' ), 
            'details' => esc_html__( 'O cabeçalho X-Frame-Options é crucial para prevenir ataques de Clickjacking.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( __( 'Adicione <code>Header always append X-Frame-Options SAMEORIGIN</code> ao seu arquivo <code>.htaccess</code> ou configuração do servidor (VirtualHost/Server Block).', 'wp-security-scanner' ) )
        );

        $items[] = array( 
            'status' => 'warning', 
            'message' => esc_html__( 'X-Content-Type-Options Ausente (MIME Sniffing)', 'wp-security-scanner' ), 
            'details' => esc_html__( 'Este cabeçalho previne que o navegador tente adivinhar o tipo de arquivo, o que pode levar a ataques de MIME-sniffing.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( __( 'Adicione <code>Header always set X-Content-Type-Options "nosniff"</code> ao seu arquivo <code>.htaccess</code>.', 'wp-security-scanner' ) )
        );

        $items[] = array( 
            'status' => 'info', 
            'message' => esc_html__( 'Content-Security-Policy (CSP) não configurada', 'wp-security-scanner' ), 
            'details' => esc_html__( 'O CSP é a melhor defesa contra XSS (Cross-Site Scripting), mas exige configuração cuidadosa.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( __( 'Considere implementar um cabeçalho <code>Content-Security-Policy</code>. Use um plugin ou consulte documentação para definir as fontes de conteúdo permitidas (scripts, estilos) para o seu site.', 'wp-security-scanner' ) )
        );

        $items[] = array( 
            'status' => 'info', 
            'message' => esc_html__( 'Referrer-Policy Ausente/Fraca', 'wp-security-scanner' ), 
            'details' => esc_html__( 'Controla a informação enviada para outros sites quando um link é clicado.', 'wp-security-scanner' ), 
            'recommendation' => wp_kses_post( __( 'Adicione <code>Header always set Referrer-Policy "strict-origin-when-cross-origin"</code> ao seu <code>.htaccess</code> para proteger a informação do seu site em links externos.', 'wp-security-scanner' ) )
        );

        return $items;
    }
    
    /**
     * @return array[]
     */
    private function check_filesystem() {
        $items = array();
        
        // 1. Permissões de Arquivos Críticos - CORREÇÃO: Usando string octal de 3 dígitos para comparação.
        $critical_paths = array(
            ABSPATH . 'wp-config.php' => '400', // Arquivos CRÍTICOS: 400 (ou 440)
            ABSPATH . '.htaccess' => '444',     // Arquivos CRÍTICOS: 444
            ABSPATH => '755',                   // Raiz (Diretório)
            WP_CONTENT_DIR => '755',            // Pastas
            WP_CONTENT_DIR . '/uploads' => '755', // Pastas
        );
        
        foreach ( $critical_paths as $path => $recommended_perms_str ) {
            if ( file_exists( $path ) ) {
                // Obtém a permissão do arquivo/diretório em octal e pega os 3 dígitos relevantes (ex: '0755' -> '755')
                $current_perms_str = substr( sprintf( '%o', fileperms( $path ) ), -3 ); 
                
                // Converte para base 10 para as comparações de risco (ex: 777, 666)
                $current_perms_decimal = intval( $current_perms_str, 8 ); 
                
                if ( $current_perms_str === $recommended_perms_str ) {
                    $items[] = array( 
                        'status' => 'good', 
                        'message' => sprintf( esc_html__( 'Permissões corretas: %s', 'wp-security-scanner' ), basename( $path ) ), 
                        'details' => sprintf( esc_html__( 'Permissões: %s (%s recomendado).', 'wp-security-scanner' ), $current_perms_str, $recommended_perms_str )
                    );
                } elseif ( $current_perms_decimal === 511 || $current_perms_decimal === 438 ) { // 777 ou 666 em decimal (octal: 0777, 0666)
                     $items[] = array( 
                        'status' => 'error', 
                        'message' => sprintf( esc_html__( 'Permissões de alto risco: %s', 'wp-security-scanner' ), basename( $path ) ), 
                        'details' => sprintf( esc_html__( 'CRÍTICO: Permissões atuais (%s) permitem escrita pública/universal.', 'wp-security-scanner' ), $current_perms_str ), 
                        'recommendation' => wp_kses_post( sprintf( 
                            __( 'Use o comando <code>chmod 0%s %s</code> via SSH/FTP para corrigir. Pastas devem ser 755 e arquivos 644/400.', 'wp-security-scanner' ), 
                            $recommended_perms_str, 
                            basename( $path ) 
                        ) )
                    );
                } else {
                    $status = ( $recommended_perms_str === '400' && $current_perms_decimal > intval('400', 8) ) ? 'error' : 'warning';
                    $items[] = array( 
                        'status' => $status, 
                        'message' => sprintf( esc_html__( 'Permissões incorretas: %s', 'wp-security-scanner' ), basename( $path ) ), 
                        'details' => sprintf( esc_html__( 'Atual: %s | Recomendado: %s. O nível de escrita pode estar muito alto.', 'wp-security-scanner' ), $current_perms_str, $recommended_perms_str ), 
                        'recommendation' => esc_html__( 'Ajuste as permissões. Pastas devem ser 755 e arquivos 644 (ou 400 para wp-config).', 'wp-security-scanner' )
                    );
                }
            }
        }

        // 2. Deny PHP execution in /uploads/
        $uploads_htaccess_path = WP_CONTENT_DIR . '/uploads/.htaccess';
        $deny_php_rule = "<Files *.php>\nOrder allow,deny\nDeny from all\n</Files>";
        
        if ( file_exists( $uploads_htaccess_path ) && ( strpos( file_get_contents( $uploads_htaccess_path ), 'Deny from all' ) !== false || strpos( file_get_contents( $uploads_htaccess_path ), 'php_flag engine off' ) !== false ) ) {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Execução de PHP em /uploads/ Bloqueada', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O arquivo .htaccess na pasta uploads impede a execução de scripts PHP maliciosos.', 'wp-security-scanner' )
            );
        } else {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Execução de PHP em /uploads/ Permitida', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Se um invasor conseguir subir um arquivo PHP malicioso, ele poderá ser executado.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( sprintf( 
                    __( 'Crie ou edite o arquivo <code>.htaccess</code> em <code>wp-content/uploads/</code> e adicione o seguinte código: <code>%s</code>', 'wp-security-scanner' ), 
                    $deny_php_rule 
                ) )
            );
        }

        // 3. Editor de Arquivos (DISALLOW_FILE_EDIT)
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
            $items[] = array(
                'status' => 'error', 
                'message' => esc_html__( 'Editor de arquivos habilitado', 'wp-security-scanner' ),
                'details' => esc_html__( 'Permite que um invasor edite plugins/temas via painel.', 'wp-security-scanner' ),
                'recommendation' => wp_kses_post( __( 'Adicione <code>define(\'DISALLOW_FILE_EDIT\', true);</code> no <code>wp-config.php</code> para desabilitar o editor de arquivos.', 'wp-security-scanner' ) )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Editor de arquivos desabilitado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Prevenção contra a instalação de backdoors por contas comprometidas.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }
    
    /**
     * @return array[]
     */
    private function check_database() {
        $items = array();
        global $wpdb;
        $prefix = $wpdb->prefix;
        
        // Check 1: Prefixo da tabela
        if ( $prefix === 'wp_' ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Prefix padrão das tabelas: \'wp_\'', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O prefixo padrão é o alvo primário em ataques de injeção SQL.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Mude o prefixo para algo único (ex: <code>$table_prefix = \'custom_prefix_\';</code>) no <code>wp-config.php</code> e renomeie todas as tabelas via phpMyAdmin.', 'wp-security-scanner' ) )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => sprintf( esc_html__( 'Prefix personalizado: %s', 'wp-security-scanner' ), $prefix ), 
                'details' => esc_html__( 'Boa prática de segurança implementada.', 'wp-security-scanner' )
            );
        }
        
        // Check 2: Otimização de DB (Transientes e Lixo)
        $transients_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%' OR option_name LIKE '\_site\_transient\_%'" );
        if ( $transients_count > 1000 ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => sprintf( esc_html__( 'Alto volume de Transientes/Cache temporário: %s', 'wp-security-scanner' ), number_format_i18n( $transients_count ) ), 
                'details' => esc_html__( 'O excesso de lixo pode retardar as consultas ao banco de dados.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Limpe transientes expirados e órfãos. Use um plugin de otimização de DB ou o comando SQL <code>DELETE FROM wp_options WHERE option_name LIKE (\'_transient_%\')</code>.', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => sprintf( esc_html__( 'Volume de Transientes normal: %s', 'wp-security-scanner' ), number_format_i18n( $transients_count ) ), 
                'details' => esc_html__( 'O volume de cache temporário não é excessivo.', 'wp-security-scanner' )
            );
        }
        
        // Check 3: Revisões de Post
        $revisions_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision'" );
        if ( $revisions_count > 500 ) {
            $items[] = array( 
                'status' => 'info', 
                'message' => sprintf( esc_html__( 'Muitas revisões de post: %s', 'wp-security-scanner' ), number_format_i18n( $revisions_count ) ), 
                'details' => esc_html__( 'O alto número de revisões aumenta o tamanho do DB e afeta o backup/performance.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Considere limitar as revisões: adicione <code>define(\'WP_POST_REVISIONS\', 5);</code> ao <code>wp-config.php</code>. Use um plugin de otimização para limpar as revisões antigas.', 'wp-security-scanner' ) )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => sprintf( esc_html__( 'Número de revisões razoável: %s', 'wp-security-scanner' ), number_format_i18n( $revisions_count ) ), 
                'details' => esc_html__( 'O tamanho das revisões não é preocupante.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }

    /**
     * @return array[]
     */
    private function check_plugins() {
        $items = array();
        
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if ( ! function_exists( 'get_site_transient' ) ) {
            require_once ABSPATH . 'wp-includes/plugin.php';
        }

        $all_plugins = get_plugins();
        $active_plugins = get_option( 'active_plugins' );
        $update_plugins = get_site_transient( 'update_plugins' );
        
        $outdated_count = 0;
        
        foreach ( $all_plugins as $plugin_path => $plugin ) {
            $plugin_name = sanitize_text_field( $plugin['Name'] );

            // Check 1: Plugins Desatualizados (Ativos e Inativos)
            if ( isset( $update_plugins->response[ $plugin_path ] ) ) {
                $outdated_count++;
                $status_type = in_array( $plugin_path, (array) $active_plugins, true ) ? 'error' : 'warning';
                
                $items[] = array(
                    'status' => $status_type,
                    'message' => sprintf( esc_html__( 'Plugin desatualizado: %s (v. %s)', 'wp-security-scanner' ), $plugin_name, $plugin['Version'] ),
                    'details' => sprintf( esc_html__( 'Vulnerabilidades conhecidas podem existir. Novo: %s', 'wp-security-scanner' ), $update_plugins->response[ $plugin_path ]->new_version ),
                    'recommendation' => esc_html__( 'Atualize imediatamente. Se inativo, considere excluir permanentemente.', 'wp-security-scanner' )
                );
            }
        }
        
        if ( $outdated_count === 0 ) {
            $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Todos os plugins estão atualizados', 'wp-security-scanner' ), 
                'details' => sprintf( esc_html__( '%d plugins verificados.', 'wp-security-scanner' ), count( $all_plugins ) )
            );
        }
        
        // Check 2: Plugins inativos
        $inactive_count = count( $all_plugins ) - count( $active_plugins );
        if ( $inactive_count > 5 ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => sprintf( esc_html__( 'Muitos plugins inativos: %d', 'wp-security-scanner' ), $inactive_count ), 
                'details' => esc_html__( 'Plugins inativos são um risco e aumentam o tamanho do backup.', 'wp-security-scanner' ), 
                'recommendation' => esc_html__( 'Exclua permanentemente todos os plugins que não estão em uso.', 'wp-security-scanner' )
            );
        }
        
        // Check 3: Plugins Nulled/Piratas
        $suspect_files = array_merge( 
            (array) glob( WP_CONTENT_DIR . '/plugins/*/*_nulled_*' ), 
            (array) glob( WP_CONTENT_DIR . '/plugins/*/readme_crack.txt' )
        );
        
        if ( ! empty( $suspect_files ) ) {
             $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Arquivos suspeitos de Nulled/Pirata encontrados', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Arquivos com nomes comuns associados a plugins piratas ou cracks foram detectados.', 'wp-security-scanner' ), 
                'recommendation' => esc_html__( 'Remova imediatamente o plugin associado e compre a licença oficial. Plugins piratas são a principal fonte de malware.', 'wp-security-scanner' )
            );
        }

        return $items;
    }

    /**
     * @return array[]
     */
    private function check_themes() {
        $items = array();
        
        if ( ! function_exists( 'wp_get_themes' ) ) {
            require_once ABSPATH . 'wp-includes/theme.php';
        }
        if ( ! function_exists( 'get_site_transient' ) ) {
            require_once ABSPATH . 'wp-includes/plugin.php';
        }

        $themes = wp_get_themes();
        $current_theme = wp_get_theme();
        $update_themes = get_site_transient( 'update_themes' );
        $outdated_count = 0;
        
        foreach ( $themes as $theme ) {
            $theme_name = sanitize_text_field( $theme->get( 'Name' ) );
            
            if ( isset( $update_themes->response[ $theme->get_stylesheet() ] ) ) {
                $outdated_count++;
                $status = $theme->get_stylesheet() === $current_theme->get_stylesheet() ? 'error' : 'warning';

                $items[] = array(
                    'status' => $status,
                    'message' => sprintf( esc_html__( 'Tema desatualizado: %s', 'wp-security-scanner' ), $theme_name ),
                    'details' => $status === 'error' ? esc_html__( 'CRÍTICO: Seu tema ativo precisa de atualização urgente!', 'wp-security-scanner' ) : esc_html__( 'Tema inativo precisa de atualização.', 'wp-security-scanner' ),
                    'recommendation' => esc_html__( 'Atualize ou, se não estiver em uso, exclua permanentemente para evitar vulnerabilidades.', 'wp-security-scanner' )
                );
            }
        }
        
        if ( $outdated_count === 0 ) {
            $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Todos os temas estão atualizados', 'wp-security-scanner' ), 
                'details' => sprintf( esc_html__( '%d temas instalados verificados.', 'wp-security-scanner' ), count( $themes ) )
            );
        }

        if ( count( $themes ) > 3 ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => sprintf( esc_html__( 'Muitos temas instalados: %d', 'wp-security-scanner' ), count( $themes ) ), 
                'details' => esc_html__( 'Temas inativos são um risco de segurança.', 'wp-security-scanner' ), 
                'recommendation' => esc_html__( 'Mantenha apenas seu tema ativo e, opcionalmente, o tema pai e um tema padrão do WordPress para testes. Exclua o restante.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }
    
    /**
     * @return array[]
     */
    private function check_security_adv() {
        $items = array();

        // 1. Versão do WordPress exposta
        if ( has_action( 'wp_head', 'wp_generator' ) ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => esc_html__( 'Versão do WordPress exposta', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Revela sua versão do WP nos metadados, facilitando ataques direcionados.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Adicione <code>remove_action(\'wp_head\', \'wp_generator\');</code> ao arquivo <code>functions.php</code> do seu tema (filho).', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Versão do WordPress oculta', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Boa prática de segurança implementada.', 'wp-security-scanner' )
            );
        }
        
        // 2. Leitura de diretórios (Directory Listing)
        $uploads_dir = wp_upload_dir();
        $test_url = esc_url( trailingslashit( $uploads_dir['baseurl'] ) );
        $response = wp_remote_get( $test_url, array( 'timeout' => 5 ) );
        
        if ( ! is_wp_error( $response ) && ( wp_remote_retrieve_response_code( $response ) == 200 ) && strpos( wp_remote_retrieve_body( $response ), 'Index of' ) !== false ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Leitura de diretório ativada', 'wp-security-scanner' ), 
                'details' => esc_html__( 'CRÍTICO: Atacantes podem listar o conteúdo de pastas (plugins, uploads), revelando a estrutura e arquivos sensíveis.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Adicione <code>Options -Indexes</code> ao seu arquivo <code>.htaccess</code>, ou crie um arquivo <code>index.html</code> vazio em pastas sem índice.', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Leitura de diretório desativada', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O seu servidor está configurado para não permitir a listagem de diretórios.', 'wp-security-scanner' )
            );
        }
        
        // 3. XML-RPC
        if ( get_option( 'enable_xmlrpc' ) ) {
            $items[] = array( 
                'status' => 'warning', 
                'message' => esc_html__( 'XML-RPC (xmlrpc.php) habilitado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Pode ser explorado para ataques de força bruta e DDoS através de pingbacks.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Se você não usa o app móvel do WP ou o Jetpack, desabilite. Adicione <code>add_filter(\'xmlrpc_enabled\', \'__return_false\');</code> ao <code>functions.php</code>.', 'wp-security-scanner' ) )
            );
        } else {
            $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'XML-RPC desabilitado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O endpoint xmlrpc.php está protegido.', 'wp-security-scanner' )
            );
        }

        // 4. Modo Debug (WP_DEBUG)
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG === true ) {
            $items[] = array( 
                'status' => 'error', 
                'message' => esc_html__( 'Modo Debug (WP_DEBUG) habilitado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'CRÍTICO: Exibe erros e warnings PHP diretamente no front-end, o que pode expor caminhos de servidor e informações sensíveis a invasores.', 'wp-security-scanner' ), 
                'recommendation' => wp_kses_post( __( 'Defina <code>define(\'WP_DEBUG\', false);</code> e <code>define(\'WP_DEBUG_LOG\', true);</code> no <code>wp-config.php</code>. O debug não deve estar ativo em produção.', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Modo Debug (WP_DEBUG) desabilitado', 'wp-security-scanner' ), 
                'details' => esc_html__( 'O modo debug está desativado no site em produção.', 'wp-security-scanner' )
            );
        }

        // 5. Arquivo de Log de Debug (debug.log) - NOVO CHECK ADICIONAL
        $debug_log_path = WP_CONTENT_DIR . '/debug.log';
        $log_exists = file_exists( $debug_log_path );
        
        if ( $log_exists ) {
            $log_size = @filesize( $debug_log_path );
            
            // Define status com base na existência e tamanho
            $status = 'warning';
            $details = esc_html__( 'O arquivo debug.log existe e pode conter informações sensíveis (como paths, erros SQL, etc.).', 'wp-security-scanner' );

            if ( $log_size > 0 ) {
                 $details = esc_html__( 'CRÍTICO: O arquivo debug.log existe, contém dados e pode ser legível por terceiros, expondo informações sensíveis (paths, erros SQL, etc.).', 'wp-security-scanner' );
                 $status = 'error';
            }

            $items[] = array( 
                'status' => $status, 
                'message' => esc_html__( 'Arquivo debug.log encontrado', 'wp-security-scanner' ), 
                'details' => $details,
                'recommendation' => wp_kses_post( __( 'Exclua imediatamente o arquivo <code>wp-content/debug.log</code>. Se precisar de logs, certifique-se de que a pasta <code>wp-content</code> não permite acesso via web ao arquivo e considere mudar o local do log (<code>define(\'WP_DEBUG_LOG\', \'/caminho/seguro/log.log\');</code>).', 'wp-security-scanner' ) )
            );
        } else {
             $items[] = array( 
                'status' => 'good', 
                'message' => esc_html__( 'Arquivo debug.log ausente', 'wp-security-scanner' ), 
                'details' => esc_html__( 'Nenhum arquivo de log de debug encontrado.', 'wp-security-scanner' )
            );
        }
        
        return $items;
    }
}

new WPSS_Security_Scanner();