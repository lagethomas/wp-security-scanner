🛡️ WP Security Scanner PRO
🌟 Visão Geral
O WP Security Scanner PRO é um plugin robusto de diagnóstico de segurança e hardening para WordPress. Ele executa uma verificação completa em seu ambiente, cobrindo mais de 30 pontos de segurança críticos em 10 categorias, desde a versão do PHP até as configurações de cabeçalhos HTTP e hardening do sistema de arquivos.

O objetivo é fornecer um relatório detalhado com o status de cada item (✅ Bom, ⚠️ Aviso, ❌ Erro) e apresentar recomendações de blindagem acionáveis para que você possa corrigir vulnerabilidades e reforçar a segurança do seu site de forma proativa.

✨ Recursos Principais
Verificação em 10 Pontos Críticos: Análise segmentada de WordPress Core, PHP, Chaves de Segurança, Login, HTTP Headers, Filesystem, Banco de Dados, Plugins, Temas e Configurações de Segurança Avançada.

Diagnóstico em Tempo Real: Execução do scan via AJAX na página de administração do WordPress, com barra de progresso e resultados dinâmicos.

Recomendações Práticas: Para cada vulnerabilidade detectada (Status: Erro ou Aviso), o plugin fornece a Recomendação exata, muitas vezes com snippets de código (.htaccess, wp-config.php) ou plugins sugeridos.

Hardening de Alto Nível: Inclui checagens complexas como permissões de arquivos críticos (ex: wp-config.php), bloqueio de PHP em /uploads/, e análise de HTTP Security Headers (X-Frame-Options, X-Content-Type-Options).

Boas Práticas de Performance: Alerta sobre excesso de lixo no banco de dados (transientes, revisões de post) que afetam a performance e o tamanho do backup.

🚀 Instalação e Uso
Instalação
Faça o download do arquivo ZIP do plugin.

No seu painel de administração do WordPress, vá para Plugins > Adicionar Novo.

Clique em Enviar Plugin e selecione o arquivo ZIP baixado.

Clique em Instalar Agora e depois em Ativar Plugin.

Como usar
Após a ativação, um novo item de menu chamado Security Scanner (com ícone de escudo 🛡️) será adicionado ao seu painel principal.

Clique em Security Scanner no menu lateral.

Na página principal do plugin, clique no botão 🔍 Executar Verificação Completa.

A barra de progresso será exibida, e o plugin começará a percorrer os 10 passos de verificação.

Ao final, os resultados aparecerão, categorizados por seção, indicando o Status e a Recomendação para cada item.

📋 Categorias de Verificação (Scan Steps)
O plugin verifica as seguintes áreas críticas do seu site:

Slug	Título da Seção	Descrição da Verificação
wordpress	⚙️ WordPress Core	Versão do WP, uso de HTTPS/SSL e FORCE_SSL_ADMIN.
php	🔧 Configurações do PHP	Versão do PHP (crítico para segurança e performance) e memory_limit.
security_keys	🔑 Chaves de Segurança e SALT	Checagem da existência e força das 8 chaves de criptografia no wp-config.php.
login_security	🛡️ Login e Força Bruta	Vulnerabilidades de login: Usuário admin padrão, limite de tentativas, 2FA e enumeração de usuários.
http_headers	🌐 HTTP Headers	Defesa de borda contra Clickjacking, MIME Sniffing e proteção de referência.
filesystem	📁 Hardening do Sistema de Arquivos	Permissões de arquivos críticos (wp-config.php, .htaccess), bloqueio de execução de PHP em /uploads/ e DISALLOW_FILE_EDIT.
database	🗃️ Banco de Dados e Usuários	Prefixo de tabela padrão (wp_), volume de transientes e revisões de post.
plugins	🔌 Plugins	Plugins desatualizados (risco de vulnerabilidades) e detecção de arquivos suspeitos (Nulled/Pirata).
themes	🎨 Temas	Temas desatualizados (ativo e inativos) e excesso de temas instalados.
security_adv	🔒 Segurança Avançada	Ocultar a versão do WP, Directory Listing, XML-RPC e Modo Debug (WP_DEBUG).

Exportar para as Planilhas
💡 Dicas Rápidas de Blindagem
A sidebar do plugin também apresenta as seguintes recomendações essenciais de segurança:

Backup: Mantenha sempre um backup recente e externo (fora do servidor).

Senhas: Use senhas longas e complexas com um gerenciador de senhas.

Usuários: Nunca use o usuário admin e utilize nomes de usuário complexos para a conta principal.

Hospedagem: Prefira hospedagens que ofereçam WAF (Web Application Firewall) e detecção de malware em tempo real.

Princípio do Mínimo Privilégio: Dê a cada usuário apenas as permissões essenciais para o seu trabalho.

🤝 Contato e Suporte
O plugin WP Security Scanner PRO é um desenvolvimento da WPMasters.

Autor: Thomas Marcelino

Site Oficial: https://wpmasters.com.br

Suporte: Entre em contato através do nosso site para suporte e dúvidas sobre a versão PRO.